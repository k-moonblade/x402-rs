//! x402 EVM flow: verification (off-chain) and settlement (on-chain).
//!
//! - **Verify**: simulate signature validity and transfer atomically in a single `eth_call`.
//!   For 6492 signatures, we call the universal validator which may *prepare* (deploy) the
//!   counterfactual wallet inside the same simulation.
//! - **Settle**: if the signer wallet is not yet deployed, we deploy it (via the 6492
//!   factory+calldata) and then call the appropriate transfer method in a real tx.
//!
//! This module is organized into:
//! - `authorization`: ERC-3009 transferWithAuthorization handling
//! - `permit`: EIP-2612 permit + transferFrom handling
//!
//! Assumptions:
//! - Target tokens implement the appropriate standard (ERC-3009 or EIP-2612)
//!   and support ERC-1271 for contract signers.
//! - The validator contract exists at [`VALIDATOR_ADDRESS`] on supported chains.
//!
//! Invariants:
//! - Settlement is atomic: deploy (if needed) + transfer happen in a single user flow.
//! - Verification does not persist state.

mod authorization;
mod permit;

use alloy::network::{
    Ethereum as AlloyEthereum, EthereumWallet, NetworkWallet, TransactionBuilder,
};
use alloy::primitives::{Address, Bytes, U256, address};
use alloy::providers::ProviderBuilder;
use alloy::providers::fillers::NonceManager;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use alloy::providers::{
    Identity, Provider, RootProvider, WalletProvider,
};
use alloy::rpc::client::RpcClient;
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::sol_types::{Eip712Domain, eip712_domain};
use alloy::{sol};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tracing::{Instrument, instrument};
use std::future::Future;

use crate::chain::{FacilitatorLocalError, FromEnvByNetworkBuild, NetworkProviderOps};
use crate::facilitator::Facilitator;
use crate::from_env;
use crate::network::{Network, USDCDeployment};
use crate::timestamp::UnixTimestamp;
use crate::types::{
    EvmAddress, ExactPaymentPayload,
    MixedAddress, PaymentPayload, PaymentRequirements, Scheme, SettleRequest,
    SettleResponse, SupportedPaymentKind, SupportedPaymentKindsResponse, TokenAmount,
    VerifyRequest, VerifyResponse, X402Version,
};

// Re-export specific functions from submodules
pub use authorization::{verify_authorization, settle_authorization};
pub use permit::{verify_permit, settle_permit};

sol!(
    #[allow(missing_docs)]
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug)]
    #[sol(rpc)]
    USDC,
    "abi/USDC.json"
);

sol! {
    #[allow(missing_docs)]
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug)]
    #[sol(rpc)]
    Validator6492,
    "abi/Validator6492.json"
}

sol! {
    #[allow(missing_docs)]
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug)]
    #[sol(rpc)]
    IERC20Permit,
    "abi/IERC20Permit.json"
}

/// Signature verifier for EIP-6492, EIP-1271, EOA, universally deployed on the supported EVM chains
/// If absent on a target chain, verification will fail; you should deploy the validator there.
const VALIDATOR_ADDRESS: alloy::primitives::Address =
    address!("0xdAcD51A54883eb67D95FAEb2BBfdC4a9a6BD2a3B");

/// Combined filler type for gas, blob gas, nonce, and chain ID.
type InnerFiller = JoinFill<
    GasFiller,
    JoinFill<BlobGasFiller, JoinFill<NonceFiller<PendingNonceManager>, ChainIdFiller>>,
>;

/// The fully composed Ethereum provider type used in this project.
///
/// Combines multiple filler layers for gas, nonce, chain ID, blob gas, and wallet signing,
/// and wraps a [`RootProvider`] for actual JSON-RPC communication.
pub type InnerProvider = FillProvider<
    JoinFill<JoinFill<Identity, InnerFiller>, WalletFiller<EthereumWallet>>,
    RootProvider,
>;

/// Chain descriptor used by the EVM provider.
///
/// Wraps a `Network` enum and the concrete `chain_id` used for EIP-155 and EIP-712.
#[derive(Clone, Copy, Debug)]
pub struct EvmChain {
    /// x402 network name (Base, Avalanche, etc.).
    pub network: Network,
    /// Numeric chain id used in transactions and EIP-712 domains.
    pub chain_id: u64,
}

impl EvmChain {
    /// Construct a chain descriptor from a network and chain id.
    pub fn new(network: Network, chain_id: u64) -> Self {
        Self { network, chain_id }
    }

    /// Returns the x402 network.
    pub fn network(&self) -> Network {
        self.network
    }
}

impl TryFrom<Network> for EvmChain {
    type Error = FacilitatorLocalError;

    /// Map a `Network` to its canonical `chain_id`.
    ///
    /// # Errors
    /// Returns [`FacilitatorLocalError::UnsupportedNetwork`] for non-EVM networks (e.g. Solana).
    fn try_from(value: Network) -> Result<Self, Self::Error> {
        match value {
            Network::BaseSepolia => Ok(EvmChain::new(value, 84532)),
            Network::Base => Ok(EvmChain::new(value, 8453)),
            Network::XdcMainnet => Ok(EvmChain::new(value, 50)),
            Network::AvalancheFuji => Ok(EvmChain::new(value, 43113)),
            Network::Avalanche => Ok(EvmChain::new(value, 43114)),
            Network::Solana => Err(FacilitatorLocalError::UnsupportedNetwork(None)),
            Network::SolanaDevnet => Err(FacilitatorLocalError::UnsupportedNetwork(None)),
            Network::PolygonAmoy => Ok(EvmChain::new(value, 80002)),
            Network::Polygon => Ok(EvmChain::new(value, 137)),
            Network::Sei => Ok(EvmChain::new(value, 1329)),
            Network::SeiTestnet => Ok(EvmChain::new(value, 1328)),
            Network::BscTestnet => Ok(EvmChain::new(value, 97)),
            Network::Bsc => Ok(EvmChain::new(value, 56)),
        }
    }
}

/// A fully specified ERC-3009 authorization payload for EVM settlement.
pub struct ExactEvmPayment {
    /// Target chain for settlement.
    #[allow(dead_code)] // Just in case.
    pub chain: EvmChain,
    /// Authorized sender (`from`) — EOA or smart wallet.
    pub from: EvmAddress,
    /// Authorized recipient (`to`).
    pub to: EvmAddress,
    /// Transfer amount (token units).
    pub value: TokenAmount,
    /// Not valid before this timestamp (inclusive).
    pub valid_after: UnixTimestamp,
    /// Not valid at/after this timestamp (exclusive).
    pub valid_before: UnixTimestamp,
    /// Unique 32-byte nonce (prevents replay).
    pub nonce: crate::types::HexEncodedNonce,
    /// Raw signature bytes (EIP-1271 or EIP-6492-wrapped).
    pub signature: crate::types::EvmSignature,
}

/// EVM implementation of the x402 facilitator.
///
/// Holds a composed Alloy ethereum provider [`InnerProvider`],
/// an `eip1559` toggle for gas pricing strategy, and the `EvmChain` context.
#[derive(Debug)]
pub struct EvmProvider {
    /// Composed Alloy provider with all fillers.
    inner: InnerProvider,
    /// Whether network supports EIP-1559 gas pricing.
    eip1559: bool,
    /// Chain descriptor (network + chain ID).
    chain: EvmChain,
    /// Available signer addresses for round-robin selection.
    signer_addresses: Arc<Vec<Address>>,
    /// Current position in round-robin signer rotation.
    signer_cursor: Arc<AtomicUsize>,
}

impl EvmProvider {
    /// Build an [`EvmProvider`] from a pre-composed Alloy ethereum provider [`InnerProvider`].
    pub async fn try_new(
        wallet: EthereumWallet,
        rpc_url: &str,
        eip1559: bool,
        network: Network,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let chain = EvmChain::try_from(network)?;
        let signer_addresses: Vec<Address> =
            NetworkWallet::<AlloyEthereum>::signer_addresses(&wallet).collect();
        if signer_addresses.is_empty() {
            return Err("wallet must contain at least one signer".into());
        }
        let signer_addresses = Arc::new(signer_addresses);
        let signer_cursor = Arc::new(AtomicUsize::new(0));
        let client = RpcClient::builder()
            .connect(rpc_url)
            .await
            .map_err(|e| format!("Failed to connect to {network}: {e}"))?;
        let filler = InnerFiller::default();
        let inner = ProviderBuilder::default()
            .filler(filler)
            .wallet(wallet)
            .connect_client(client);

        tracing::info!(network=%network, rpc=rpc_url, signers=?signer_addresses, "Initialized provider");

        Ok(Self {
            inner,
            eip1559,
            chain,
            signer_addresses,
            signer_cursor,
        })
    }

    /// Round-robin selection of next signer from wallet.
    fn next_signer_address(&self) -> Address {
        debug_assert!(!self.signer_addresses.is_empty());
        if self.signer_addresses.len() == 1 {
            self.signer_addresses[0]
        } else {
            let next =
                self.signer_cursor.fetch_add(1, Ordering::Relaxed) % self.signer_addresses.len();
            self.signer_addresses[next]
        }
    }
}

/// Trait for sending meta-transactions with custom target and calldata.
pub trait MetaEvmProvider {
    /// Error type for operations.
    type Error;
    /// Underlying provider type.
    type Inner: Provider;

    /// Returns reference to underlying provider.
    fn inner(&self) -> &Self::Inner;
    /// Returns reference to chain descriptor.
    fn chain(&self) -> &EvmChain;

    /// Sends a meta-transaction to the network.
    fn send_transaction(
        &self,
        tx: MetaTransaction,
    ) -> impl Future<Output = Result<TransactionReceipt, Self::Error>> + Send;
}

/// Meta-transaction parameters: target address, calldata, and required confirmations.
pub struct MetaTransaction {
    /// Target contract address.
    pub to: Address,
    /// Transaction calldata (encoded function call).
    pub calldata: Bytes,
    /// Number of block confirmations to wait for.
    pub confirmations: u64,
}

impl MetaEvmProvider for EvmProvider {
    type Error = FacilitatorLocalError;
    type Inner = InnerProvider;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    fn chain(&self) -> &EvmChain {
        &self.chain
    }

    /// Send a meta-transaction with provided `to`, `calldata`, and automatically selected signer.
    ///
    /// This method constructs a transaction from the provided [`MetaTransaction`], automatically
    /// selects the next available signer using round-robin selection, and handles gas pricing
    /// based on whether the network supports EIP-1559.
    ///
    /// # Gas Pricing Strategy
    ///
    /// - **EIP-1559 networks**: Uses automatic gas pricing via the provider's fillers.
    /// - **Legacy networks**: Fetches the current gas price using `get_gas_price()` and sets it explicitly.
    ///
    /// # Parameters
    ///
    /// - `tx`: A [`MetaTransaction`] containing the target address and calldata.
    ///
    /// # Returns
    ///
    /// A [`TransactionReceipt`] once the transaction has been mined and confirmed.
    ///
    /// # Errors
    ///
    /// Returns [`FacilitatorLocalError::ContractCall`] if:
    /// - Gas price fetching fails (on legacy networks)
    /// - Transaction sending fails
    /// - Receipt retrieval fails
    async fn send_transaction(
        &self,
        tx: MetaTransaction,
    ) -> Result<TransactionReceipt, Self::Error> {
        let mut txr = TransactionRequest::default()
            .with_to(tx.to)
            .with_from(self.next_signer_address())
            .with_input(tx.calldata);
        if !self.eip1559 {
            let provider = &self.inner;
            let gas: u128 = provider
                .get_gas_price()
                .instrument(tracing::info_span!("get_gas_price"))
                .await
                .map_err(|e| FacilitatorLocalError::ContractCall(format!("{e:?}")))?;
            txr.set_gas_price(gas);
        }
        let pending_tx = self
            .inner
            .send_transaction(txr)
            .await
            .map_err(|e| FacilitatorLocalError::ContractCall(format!("{e:?}")))?;
        pending_tx
            .with_required_confirmations(tx.confirmations)
            .get_receipt()
            .await
            .map_err(|e| FacilitatorLocalError::ContractCall(format!("{e:?}")))
    }
}

impl NetworkProviderOps for EvmProvider {
    /// Address of the default signer used by this provider (for tx sending).
    fn signer_address(&self) -> MixedAddress {
        self.inner.default_signer_address().into()
    }

    /// x402 network handled by this provider.
    fn network(&self) -> Network {
        self.chain.network
    }
}

impl FromEnvByNetworkBuild for EvmProvider {
    async fn from_env(network: Network) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let env_var = from_env::rpc_env_name_from_network(network);
        let rpc_url = match std::env::var(env_var).ok() {
            Some(rpc_url) => rpc_url,
            None => {
                tracing::warn!(network=%network, "no RPC URL configured, skipping");
                return Ok(None);
            }
        };
        let wallet = from_env::SignerType::from_env()?.make_evm_wallet()?;
        let is_eip1559 = match network {
            Network::BaseSepolia => true,
            Network::Base => true,
            Network::XdcMainnet => false,
            Network::AvalancheFuji => true,
            Network::Avalanche => true,
            Network::Solana => false,
            Network::SolanaDevnet => false,
            Network::PolygonAmoy => true,
            Network::Polygon => true,
            Network::Sei => true,
            Network::SeiTestnet => true,
            Network::BscTestnet => true,
            Network::Bsc => true,
        };
        let provider = EvmProvider::try_new(wallet, &rpc_url, is_eip1559, network).await?;
        Ok(Some(provider))
    }
}

impl<P> Facilitator for P
where
    P: MetaEvmProvider + Sync,
    FacilitatorLocalError: From<P::Error>,
{
    type Error = FacilitatorLocalError;

    /// Verify x402 payment intent.
    ///
    /// Auto-detects payment method based on payload type:
    /// - `ExactPaymentPayload::EvmPermit` → EIP-2612 permit verification
    /// - `ExactPaymentPayload::Evm` → ERC-3009 authorization verification
    ///
    /// # Errors
    /// - [`FacilitatorLocalError::NetworkMismatch`], [`FacilitatorLocalError::ReceiverMismatch`] if inputs are inconsistent.
    /// - [`FacilitatorLocalError::InvalidTiming`] if outside `validAfter/validBefore` or permit deadline.
    /// - [`FacilitatorLocalError::InsufficientFunds`] / `FacilitatorLocalError::InsufficientValue` on balance/value checks.
    /// - [`FacilitatorLocalError::ContractCall`] if on-chain calls revert.
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;

        tracing::info!(
            network = %self.chain().network(),
            scheme = %payload.scheme,
            "Routing verify request"
        );

        // Deterministic routing based on payload type
        match &payload.payload {
            ExactPaymentPayload::EvmPermit(permit_payload) => {
                tracing::info!("EvmPermit payload → using EIP-2612 permit verification");
                verify_permit(self.inner(), permit_payload).await
            }
            ExactPaymentPayload::Evm(_) => {
                tracing::info!("Evm payload → using ERC-3009 authorization verification");
                verify_authorization(self, payload, requirements).await
            }
            ExactPaymentPayload::Solana(_) => {
                tracing::error!("Solana payload not supported on EVM");
                Err(FacilitatorLocalError::UnsupportedNetwork(None))
            }
        }
    }

    /// Settle a verified payment on-chain.
    ///
    /// Auto-detects payment method based on payload type:
    /// - `ExactPaymentPayload::EvmPermit` → EIP-2612 permit settlement (permit + transferFrom via Multicall3)
    /// - `ExactPaymentPayload::Evm` → ERC-3009 authorization settlement (transferWithAuthorization)
    ///
    /// # Returns
    /// A [`SettleResponse`] containing success flag and transaction hash.
    ///
    /// # Errors
    /// Propagates [`FacilitatorLocalError::ContractCall`] on deployment or transfer failures
    /// and all prior validation errors.
    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;

        tracing::info!(
            network = %self.chain().network(),
            scheme = %payload.scheme,
            "Routing settle request"
        );

        // Deterministic routing based on payload type
        match &payload.payload {
            ExactPaymentPayload::EvmPermit(permit_payload) => {
                tracing::info!("EvmPermit payload → using EIP-2612 permit settlement");
                settle_permit(self, permit_payload, payload.network).await
            }
            ExactPaymentPayload::Evm(_) => {
                tracing::info!("Evm payload → using ERC-3009 authorization settlement");
                settle_authorization(self, payload, requirements).await
            }
            ExactPaymentPayload::Solana(_) => {
                tracing::error!("Solana payload not supported on EVM");
                Err(FacilitatorLocalError::UnsupportedNetwork(None))
            }
        }
    }

    /// Report payment kinds supported by this provider on its current network.
    ///
    /// Always returns Scheme::Exact - the facilitator auto-detects whether to use
    /// EIP-2612 permit or ERC-3009 authorization based on the payload type.
    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        let network = self.chain().network();

        tracing::info!(
            network = %network,
            "Returning Scheme::Exact - auto-detection handles permit vs authorization"
        );

        let kinds = vec![SupportedPaymentKind {
            network: network.to_string(),
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            extra: None,
        }];
        Ok(SupportedPaymentKindsResponse { kinds })
    }
}

/// Validates that the current time is within the `validAfter` and `validBefore` bounds.
///
/// Adds a 6-second grace buffer when checking expiration to account for latency.
///
/// # Errors
/// Returns [`FacilitatorLocalError::InvalidTiming`] if the authorization is not yet active or already expired.
/// Returns [`FacilitatorLocalError::ClockError`] if the system clock cannot be read.
#[instrument(skip_all, err)]
fn assert_time(
    payer: MixedAddress,
    valid_after: UnixTimestamp,
    valid_before: UnixTimestamp,
) -> Result<(), FacilitatorLocalError> {
    let now = UnixTimestamp::try_now().map_err(FacilitatorLocalError::ClockError)?;
    if valid_before < now + 6 {
        return Err(FacilitatorLocalError::InvalidTiming(
            payer,
            format!("Expired: now {} > valid_before {}", now + 6, valid_before),
        ));
    }
    if valid_after > now {
        return Err(FacilitatorLocalError::InvalidTiming(
            payer,
            format!("Not active yet: valid_after {valid_after} > now {now}",),
        ));
    }
    Ok(())
}

/// Checks if the payer has enough on-chain token balance to meet the `maxAmountRequired`.
///
/// Performs an `ERC20.balanceOf()` call using the USDC contract instance.
///
/// # Errors
/// Returns [`FacilitatorLocalError::InsufficientFunds`] if the balance is too low.
/// Returns [`FacilitatorLocalError::ContractCall`] if the balance query fails.
#[instrument(skip_all, err, fields(
    sender = %sender,
    max_required = %max_amount_required,
    token_contract = %usdc_contract.address()
))]
async fn assert_enough_balance<P: Provider>(
    usdc_contract: &USDC::USDCInstance<P>,
    sender: &EvmAddress,
    max_amount_required: U256,
) -> Result<(), FacilitatorLocalError> {
    let balance = usdc_contract
        .balanceOf(sender.0)
        .call()
        .into_future()
        .instrument(tracing::info_span!(
            "fetch_token_balance",
            token_contract = %usdc_contract.address(),
            sender = %sender,
            otel.kind = "client"
        ))
        .await
        .map_err(|e| FacilitatorLocalError::ContractCall(format!("{e:?}")))?;

    if balance < max_amount_required {
        Err(FacilitatorLocalError::InsufficientFunds((*sender).into()))
    } else {
        Ok(())
    }
}

/// Verifies that the declared `value` in the payload is sufficient for the required amount.
///
/// This is a static check (not on-chain) that compares two numbers.
///
/// # Errors
/// Return [`FacilitatorLocalError::InsufficientValue`] if the payload's value is less than required.
#[instrument(skip_all, err, fields(
    sent = %sent,
    max_amount_required = %max_amount_required
))]
fn assert_enough_value(
    payer: &EvmAddress,
    sent: &U256,
    max_amount_required: &U256,
) -> Result<(), FacilitatorLocalError> {
    if sent < max_amount_required {
        Err(FacilitatorLocalError::InsufficientValue((*payer).into()))
    } else {
        Ok(())
    }
}

/// Check whether contract code is present at `address`.
///
/// Uses `eth_getCode` against this provider. This is useful after a counterfactual
/// deployment to confirm visibility on the sending RPC before submitting a
/// follow-up transaction.
///
/// # Errors
/// Return [`FacilitatorLocalError::ContractCall`] if the RPC call fails.
pub async fn is_contract_deployed<P: Provider>(
    provider: &P,
    address: &Address,
) -> Result<bool, FacilitatorLocalError> {
    let bytes = provider
        .get_code_at(*address)
        .into_future()
        .instrument(tracing::info_span!("get_code_at",
            address = %address,
            otel.kind = "client",
        ))
        .await
        .map_err(|e| FacilitatorLocalError::ContractCall(format!("{e:?}")))?;
    Ok(!bytes.is_empty())
}

/// Constructs the correct EIP-712 domain for signature verification.
///
/// Resolves the `name` and `version` based on:
/// - Static metadata from [`USDCDeployment`] (if available),
/// - Or by calling `version()` on the token contract if not matched statically.
#[instrument(skip_all, err, fields(
    network = %payload.network,
    asset = %asset_address
))]
async fn assert_domain<P: Provider>(
    chain: &EvmChain,
    token_contract: &USDC::USDCInstance<P>,
    payload: &PaymentPayload,
    asset_address: &Address,
    requirements: &PaymentRequirements,
) -> Result<Eip712Domain, FacilitatorLocalError> {
    let usdc = USDCDeployment::by_network(payload.network);
    let name = requirements
        .extra
        .as_ref()
        .and_then(|e| e.get("name")?.as_str().map(str::to_string))
        .or_else(|| usdc.eip712.clone().map(|e| e.name))
        .ok_or(FacilitatorLocalError::UnsupportedNetwork(None))?;
    let chain_id = chain.chain_id;
    let version = requirements
        .extra
        .as_ref()
        .and_then(|extra| extra.get("version"))
        .and_then(|version| version.as_str().map(|s| s.to_string()));
    let version = if let Some(extra_version) = version {
        Some(extra_version)
    } else if usdc.address() == (*asset_address).into() {
        usdc.eip712.clone().map(|e| e.version)
    } else {
        None
    };
    let version = if let Some(version) = version {
        version
    } else {
        token_contract
            .version()
            .call()
            .into_future()
            .instrument(tracing::info_span!(
                "fetch_eip712_version",
                otel.kind = "client",
            ))
            .await
            .map_err(|e| FacilitatorLocalError::ContractCall(format!("{e:?}")))?
    };
    let domain = eip712_domain! {
        name: name,
        version: version,
        chain_id: chain_id,
        verifying_contract: *asset_address,
    };
    Ok(domain)
}

/// Runs all preconditions needed for a successful payment:
/// - Valid scheme, network, and receiver.
/// - Valid time window (validAfter/validBefore).
/// - Correct EIP-712 domain construction.
/// - Sufficient on-chain balance.
/// - Sufficient value in payload.
#[instrument(skip_all, err)]
pub async fn assert_valid_payment<P: Provider>(
    provider: P,
    chain: &EvmChain,
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Result<(USDC::USDCInstance<P>, ExactEvmPayment, Eip712Domain), FacilitatorLocalError> {
    let payment_payload = match &payload.payload {
        ExactPaymentPayload::Evm(payload) => payload,
        ExactPaymentPayload::EvmPermit(_) => {
            return Err(FacilitatorLocalError::InvalidAddress(
                "EvmPermit payload not supported for ERC-3009 authorization".to_string(),
            ));
        }
        ExactPaymentPayload::Solana(_) => {
            return Err(FacilitatorLocalError::UnsupportedNetwork(None));
        }
    };
    let payer = payment_payload.authorization.from;
    if payload.network != chain.network {
        return Err(FacilitatorLocalError::NetworkMismatch(
            Some(payer.into()),
            chain.network,
            payload.network,
        ));
    }
    if requirements.network != chain.network {
        return Err(FacilitatorLocalError::NetworkMismatch(
            Some(payer.into()),
            chain.network,
            requirements.network,
        ));
    }
    if payload.scheme != requirements.scheme {
        return Err(FacilitatorLocalError::SchemeMismatch(
            Some(payer.into()),
            requirements.scheme,
            payload.scheme,
        ));
    }
    let payload_to: EvmAddress = payment_payload.authorization.to;
    let requirements_to: EvmAddress = requirements
        .pay_to
        .clone()
        .try_into()
        .map_err(|e| FacilitatorLocalError::InvalidAddress(format!("{e:?}")))?;
    if payload_to != requirements_to {
        return Err(FacilitatorLocalError::ReceiverMismatch(
            payer.into(),
            payload_to.to_string(),
            requirements_to.to_string(),
        ));
    }
    let valid_after = payment_payload.authorization.valid_after;
    let valid_before = payment_payload.authorization.valid_before;
    assert_time(payer.into(), valid_after, valid_before)?;
    let asset_address = requirements
        .asset
        .clone()
        .try_into()
        .map_err(|e| FacilitatorLocalError::InvalidAddress(format!("{e:?}")))?;
    let contract = USDC::new(asset_address, provider);

    let domain = assert_domain(chain, &contract, payload, &asset_address, requirements).await?;

    let amount_required = requirements.max_amount_required.0;
    assert_enough_balance(
        &contract,
        &payment_payload.authorization.from,
        amount_required,
    )
    .await?;
    let value: U256 = payment_payload.authorization.value.into();
    assert_enough_value(&payer, &value, &amount_required)?;

    let payment = ExactEvmPayment {
        chain: *chain,
        from: payment_payload.authorization.from,
        to: payment_payload.authorization.to,
        value: payment_payload.authorization.value,
        valid_after: payment_payload.authorization.valid_after,
        valid_before: payment_payload.authorization.valid_before,
        nonce: payment_payload.authorization.nonce,
        signature: payment_payload.signature.clone(),
    };

    Ok((contract, payment, domain))
}

/// A nonce manager that caches nonces locally and checks pending transactions on initialization.
///
/// This implementation attempts to improve upon Alloy's `CachedNonceManager` by using `.pending()` when
/// fetching the initial nonce, which includes pending transactions in the mempool. This prevents
/// "nonce too low" errors when the application restarts while transactions are still pending.
///
/// # How it works
///
/// - **First call for an address**: Attempts to fetch the nonce using `.pending()`, which includes
///   transactions in the mempool. Falls back to latest block if pending is not supported by the RPC.
/// - **Subsequent calls**: Increments the cached nonce locally without querying the RPC.
/// - **Per-address tracking**: Each address has its own cached nonce, allowing concurrent
///   transaction submission from multiple addresses.
///
/// # Thread Safety
///
/// The nonce cache is shared across all clones using `Arc<DashMap>`, ensuring that concurrent
/// requests see consistent nonce values. Each address's nonce is protected by its own `Mutex`
/// to prevent race conditions during allocation.
/// ```
#[derive(Clone, Debug, Default)]
pub struct PendingNonceManager {
    /// Cache of nonces per address. Each address has its own mutex-protected nonce value.
    nonces: Arc<DashMap<alloy::primitives::Address, Arc<Mutex<u64>>>>,
}

#[async_trait]
impl NonceManager for PendingNonceManager {
    async fn get_next_nonce<P, N>(
        &self,
        provider: &P,
        address: alloy::primitives::Address,
    ) -> alloy::transports::TransportResult<u64>
    where
        P: Provider<N>,
        N: alloy::network::Network,
    {
        // Use `u64::MAX` as a sentinel value to indicate that the nonce has not been fetched yet.
        const NONE: u64 = u64::MAX;

        // Locks dashmap internally for a short duration to clone the `Arc`.
        // We also don't want to hold the dashmap lock through the await point below.
        let nonce = {
            let rm = self
                .nonces
                .entry(address)
                .or_insert_with(|| Arc::new(Mutex::new(NONE)));
            Arc::clone(rm.value())
        };

        let mut nonce = nonce.lock().await;
        let new_nonce = if *nonce == NONE {
            // Initialize the nonce if we haven't seen this account before.
            tracing::trace!(%address, "fetching nonce");
            // Try pending first (includes mempool), fallback to latest if not supported
            let pending_result = provider.get_transaction_count(address).pending().await;
            match pending_result {
                Ok(n) => {
                    tracing::trace!(%address, nonce = n, "fetched nonce from pending");
                    n
                }
                Err(e) => {
                    tracing::debug!(%address, error = %e, "pending not supported, using latest");
                    provider.get_transaction_count(address).await?
                }
            }
        } else {
            tracing::trace!(%address, current_nonce = *nonce, "incrementing nonce");
            *nonce + 1
        };
        *nonce = new_nonce;
        Ok(new_nonce)
    }
}
