//! ERC-3009 transferWithAuthorization implementation for EVM chains.
//!
//! This module handles verification and settlement of payments using the ERC-3009
//! `transferWithAuthorization` standard, which allows gasless token transfers via
//! meta-transactions with EIP-712 signatures.
//!
//! Supports both EOA signatures, EIP-1271 contract signatures, and EIP-6492
//! counterfactual wallet signatures.

use alloy::contract::SolCallBuilder;
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::{MULTICALL3_ADDRESS, MulticallItem, Provider};
use alloy::providers::bindings::IMulticall3;
use alloy::sol_types::{Eip712Domain, SolCall, SolStruct};
use tracing::Instrument;
use tracing_core::Level;

use crate::chain::evm::{
    USDC, Validator6492, MetaEvmProvider, MetaTransaction, VALIDATOR_ADDRESS,
    assert_valid_payment, is_contract_deployed, ExactEvmPayment,
};
use crate::chain::FacilitatorLocalError;
use crate::types::{
    FacilitatorErrorReason, PaymentPayload, PaymentRequirements,
    SettleResponse, TransactionHash, VerifyResponse, TransferWithAuthorization,
};

/// A prepared call to `transferWithAuthorization` (ERC-3009) including all derived fields.
///
/// This struct wraps the assembled call builder, making it reusable across verification
/// (`.call()`) and settlement (`.send()`) flows, along with context useful for tracing/logging.
pub struct TransferWithAuthorization0Call<P> {
    /// The prepared call builder that can be `.call()`ed or `.send()`ed.
    pub tx: SolCallBuilder<P, USDC::transferWithAuthorization_0Call>,
    /// The sender (`from`) address for the authorization.
    pub from: alloy::primitives::Address,
    /// The recipient (`to`) address for the authorization.
    pub to: alloy::primitives::Address,
    /// The amount to transfer (value).
    pub value: U256,
    /// Start of the validity window (inclusive).
    pub valid_after: U256,
    /// End of the validity window (exclusive).
    pub valid_before: U256,
    /// 32-byte authorization nonce (prevents replay).
    pub nonce: FixedBytes<32>,
    /// EIP-712 signature for the transfer authorization.
    pub signature: Bytes,
    /// Address of the token contract used for this transfer.
    pub contract_address: alloy::primitives::Address,
}

/// Constructs a full `transferWithAuthorization` call for a verified payment payload.
///
/// This function prepares the transaction builder with gas pricing adapted to the network's
/// capabilities (EIP-1559 or legacy) and packages it together with signature metadata
/// into a [`TransferWithAuthorization0Call`] structure.
///
/// This function does not perform any validation — it assumes inputs are already checked.
#[allow(non_snake_case)]
pub async fn transferWithAuthorization_0<'a, P: Provider>(
    contract: &'a USDC::USDCInstance<P>,
    payment: &ExactEvmPayment,
    signature: Bytes,
) -> Result<TransferWithAuthorization0Call<&'a P>, FacilitatorLocalError> {
    let from: Address = payment.from.into();
    let to: Address = payment.to.into();
    let value: U256 = payment.value.into();
    let valid_after: U256 = payment.valid_after.into();
    let valid_before: U256 = payment.valid_before.into();
    let nonce = FixedBytes(payment.nonce.0);
    let tx = contract.transferWithAuthorization_0(
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce,
        signature.clone(),
    );
    Ok(TransferWithAuthorization0Call {
        tx,
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce,
        signature,
        contract_address: *contract.address(),
    })
}

/// A structured representation of an Ethereum signature.
///
/// This enum normalizes two supported cases:
///
/// - **EIP-6492 wrapped signatures**: used for counterfactual contract wallets.
///   They include deployment metadata (factory + calldata) plus the inner
///   signature that the wallet contract will validate after deployment.
/// - **EIP-1271 signatures**: plain contract (or EOA-style) signatures.
#[derive(Debug, Clone)]
pub enum StructuredSignature {
    /// An EIP-6492 wrapped signature.
    EIP6492 {
        /// Factory contract that can deploy the wallet deterministically
        factory: alloy::primitives::Address,
        /// Calldata to invoke on the factory (often a CREATE2 deployment).
        factory_calldata: Bytes,
        /// Inner signature for the wallet itself, probably EIP-1271.
        inner: Bytes,
        /// Full original bytes including the 6492 wrapper and magic bytes suffix.
        original: Bytes,
    },
    /// A plain EIP-1271 or EOA signature (no 6492 wrappers).
    EIP1271(Bytes),
}

/// Canonical data required to verify a signature.
#[derive(Debug, Clone)]
pub struct SignedMessage {
    /// Expected signer (an EOA or contract wallet).
    pub address: alloy::primitives::Address,
    /// 32-byte digest that was signed (typically an EIP-712 hash).
    pub hash: FixedBytes<32>,
    /// Structured signature, either EIP-6492 or EIP-1271.
    pub signature: StructuredSignature,
}

impl SignedMessage {
    /// Construct a [`SignedMessage`] from an [`ExactEvmPayment`] and its
    /// corresponding [`Eip712Domain`].
    ///
    /// This helper ties together:
    /// - The **payment intent** (an ERC-3009 `TransferWithAuthorization` struct),
    /// - The **EIP-712 domain** used for signing,
    /// - And the raw signature bytes attached to the payment.
    ///
    /// Steps performed:
    /// 1. Build an in-memory [`TransferWithAuthorization`] struct from the
    ///    `ExactEvmPayment` fields (`from`, `to`, `value`, validity window, `nonce`).
    /// 2. Compute the **EIP-712 struct hash** for that transfer under the given
    ///    `domain`. This becomes the `hash` field of the signed message.
    /// 3. Parse the raw signature bytes into a [`StructuredSignature`], which
    ///    distinguishes between:
    ///    - EIP-1271 (plain signature), and
    ///    - EIP-6492 (counterfactual signature wrapper).
    /// 4. Assemble all parts into a [`SignedMessage`] and return it.
    ///
    /// # Errors
    ///
    /// Returns [`FacilitatorLocalError`] if:
    /// - The raw signature cannot be decoded as either EIP-1271 or EIP-6492.
    pub fn extract(
        payment: &ExactEvmPayment,
        domain: &Eip712Domain,
    ) -> Result<Self, FacilitatorLocalError> {
        let transfer_with_authorization = TransferWithAuthorization {
            from: payment.from.0,
            to: payment.to.0,
            value: payment.value.into(),
            validAfter: payment.valid_after.into(),
            validBefore: payment.valid_before.into(),
            nonce: FixedBytes(payment.nonce.0),
        };
        let eip712_hash = transfer_with_authorization.eip712_signing_hash(domain);
        let expected_address = payment.from;
        let structured_signature: StructuredSignature = payment.signature.clone().try_into()?;
        let signed_message = Self {
            address: expected_address.into(),
            hash: eip712_hash,
            signature: structured_signature,
        };
        Ok(signed_message)
    }
}

/// The fixed 32-byte magic suffix defined by [EIP-6492](https://eips.ethereum.org/EIPS/eip-6492).
///
/// Any signature ending with this constant is treated as a 6492-wrapped
/// signature; the preceding bytes are ABI-decoded as `(address factory, bytes factoryCalldata, bytes innerSig)`.
const EIP6492_MAGIC_SUFFIX: [u8; 32] =
    alloy::hex!("6492649264926492649264926492649264926492649264926492649264926492");

use alloy::sol;
use crate::types::EvmSignature;

sol! {
    /// Solidity-compatible struct for decoding the prefix of an EIP-6492 signature.
    ///
    /// Matches the tuple `(address factory, bytes factoryCalldata, bytes innerSig)`.
    #[derive(Debug)]
    struct Sig6492 {
        address factory;
        bytes   factoryCalldata;
        bytes   innerSig;
    }
}

impl TryFrom<EvmSignature> for StructuredSignature {
    type Error = FacilitatorLocalError;
    /// Convert from an `EvmSignature` wrapper to a structured signature.
    ///
    /// This delegates to the `TryFrom<Vec<u8>>` implementation.
    fn try_from(signature: EvmSignature) -> Result<Self, Self::Error> {
        signature.0.try_into()
    }
}

impl TryFrom<Vec<u8>> for StructuredSignature {
    type Error = FacilitatorLocalError;

    /// Parse raw signature bytes into a `StructuredSignature`.
    ///
    /// Rules:
    /// - If the last 32 bytes equal [`EIP6492_MAGIC_SUFFIX`], the prefix is
    ///   decoded as a [`Sig6492`] struct and returned as
    ///   [`StructuredSignature::EIP6492`].
    /// - Otherwise, the bytes are returned as [`StructuredSignature::EIP1271`].
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        use alloy::dyn_abi::SolType;
        let is_eip6492 = bytes.len() >= 32 && bytes[bytes.len() - 32..] == EIP6492_MAGIC_SUFFIX;
        let signature = if is_eip6492 {
            let body = &bytes[..bytes.len() - 32];
            let sig6492 = Sig6492::abi_decode_params(body).map_err(|e| {
                FacilitatorLocalError::ContractCall(format!(
                    "Failed to decode EIP6492 signature: {e}"
                ))
            })?;
            StructuredSignature::EIP6492 {
                factory: sig6492.factory,
                factory_calldata: sig6492.factoryCalldata,
                inner: sig6492.innerSig,
                original: bytes.into(),
            }
        } else {
            StructuredSignature::EIP1271(bytes.into())
        };
        Ok(signature)
    }
}

/// Verify an ERC-3009 payment using `transferWithAuthorization`.
///
/// For EIP-6492 signatures, performs a multicall: first the validator's
/// `isValidSigWithSideEffects` (which *may* deploy the counterfactual wallet in sim),
/// then the token's `transferWithAuthorization`. Both run within a single `eth_call`
/// so the state is shared during simulation.
///
/// # Errors
/// - [`FacilitatorLocalError::ContractCall`] if on-chain calls revert.
/// - [`FacilitatorLocalError::InvalidSignature`] if signature validation fails.
pub async fn verify_authorization<P: MetaEvmProvider>(
    provider: &P,
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Result<VerifyResponse, FacilitatorLocalError>
where
    FacilitatorLocalError: From<P::Error>,
{
    tracing::info!(
        network = %payload.network,
        scheme = %payload.scheme,
        "Starting ERC-3009 authorization verification"
    );

    let (contract, payment, eip712_domain) =
        assert_valid_payment(provider.inner(), provider.chain(), payload, requirements).await?;

    tracing::info!(
        from = %payment.from,
        to = %payment.to,
        value = %payment.value,
        valid_after = %payment.valid_after,
        valid_before = %payment.valid_before,
        nonce = ?payment.nonce,
        token = %contract.address(),
        "Payment validation passed, extracting signature"
    );

    let signed_message = SignedMessage::extract(&payment, &eip712_domain)?;
    let payer = signed_message.address;
    let hash = signed_message.hash;

    tracing::info!(
        payer = %payer,
        hash = %hash,
        "Extracted signed message"
    );
    match signed_message.signature {
        StructuredSignature::EIP6492 {
            factory: _,
            factory_calldata: _,
            inner,
            original,
        } => {
            tracing::info!(
                payer = %payer,
                validator = %VALIDATOR_ADDRESS,
                "Using EIP-6492 signature validation (counterfactual wallet)"
            );

            // Prepare the call to validate EIP-6492 signature
            let validator6492 = Validator6492::new(VALIDATOR_ADDRESS, provider.inner());
            let is_valid_signature_call =
                validator6492.isValidSigWithSideEffects(payer, hash, original);
            // Prepare the call to simulate transfer the funds
            let transfer_call = transferWithAuthorization_0(&contract, &payment, inner).await?;

            tracing::info!(
                payer = %payer,
                token = %contract.address(),
                "Executing multicall: signature validation + transfer simulation"
            );

            // Execute both calls in a single transaction simulation to accommodate for possible smart wallet creation
            // Use "latest" block instead of "pending" since some RPC providers don't support pending tag
            let (is_valid_signature_result, transfer_result) = provider
                .inner()
                .multicall()
                .block(alloy::eips::BlockId::latest())
                .add(is_valid_signature_call)
                .add(transfer_call.tx)
                .aggregate3()
                .instrument(tracing::info_span!("call_transferWithAuthorization_0",
                        from = %transfer_call.from,
                        to = %transfer_call.to,
                        value = %transfer_call.value,
                        valid_after = %transfer_call.valid_after,
                        valid_before = %transfer_call.valid_before,
                        nonce = %transfer_call.nonce,
                        signature = %transfer_call.signature,
                        token_contract = %transfer_call.contract_address,
                        otel.kind = "client",
                ))
                .await
                .map_err(|e| {
                    tracing::error!(
                        payer = %payer,
                        error = %e,
                        "Multicall failed (EIP-6492 validation + transfer)"
                    );
                    FacilitatorLocalError::ContractCall(format!("{e:?}"))
                })?;
            let is_valid_signature_result = is_valid_signature_result
                .map_err(|e| {
                    tracing::error!(payer = %payer, error = %e, "Signature validation failed");
                    FacilitatorLocalError::ContractCall(format!("{e:?}"))
                })?;
            if !is_valid_signature_result {
                tracing::error!(payer = %payer, "EIP-6492 signature validation returned false");
                return Err(FacilitatorLocalError::InvalidSignature(
                    payer.into(),
                    "Incorrect signature".to_string(),
                ));
            }
            tracing::info!(payer = %payer, "✓ EIP-6492 signature validation passed");

            transfer_result.map_err(|e| {
                tracing::error!(payer = %payer, error = %e, "Transfer simulation failed");
                FacilitatorLocalError::ContractCall(format!("{e}"))
            })?;
            tracing::info!(payer = %payer, "✓ Transfer simulation passed");
        }
        StructuredSignature::EIP1271(signature) => {
            tracing::info!(
                payer = %payer,
                "Using EIP-1271/EOA signature validation"
            );

            // It is EOA or EIP-1271 signature, which we can pass to the transfer simulation
            let transfer_call =
                transferWithAuthorization_0(&contract, &payment, signature).await?;

            tracing::info!(
                payer = %payer,
                token = %contract.address(),
                "Simulating transferWithAuthorization"
            );

            transfer_call
                .tx
                .call()
                .into_future()
                .instrument(tracing::info_span!("call_transferWithAuthorization_0",
                        from = %transfer_call.from,
                        to = %transfer_call.to,
                        value = %transfer_call.value,
                        valid_after = %transfer_call.valid_after,
                        valid_before = %transfer_call.valid_before,
                        nonce = %transfer_call.nonce,
                        signature = %transfer_call.signature,
                        token_contract = %transfer_call.contract_address,
                        otel.kind = "client",
                ))
                .await
                .map_err(|e| {
                    tracing::error!(
                        payer = %payer,
                        error = %e,
                        "Transfer simulation failed (EIP-1271/EOA)"
                    );
                    FacilitatorLocalError::ContractCall(format!("{e:?}"))
                })?;

            tracing::info!(payer = %payer, "✓ Transfer simulation passed (EIP-1271/EOA)");
        }
    }

    tracing::info!(
        payer = %payer,
        "✅ ERC-3009 authorization verification succeeded - all checks passed"
    );

    Ok(VerifyResponse::valid(payer.into()))
}

/// Settle an ERC-3009 payment on-chain.
///
/// If the signer is counterfactual (EIP-6492) and the wallet is not yet deployed,
/// this submits **one** transaction to Multicall3 (`aggregate3`) that:
/// 1) calls the 6492 factory with the provided calldata (best-effort prepare),
/// 2) calls `transferWithAuthorization` with the **inner** signature.
///
/// This makes deploy + transfer atomic and avoids read-your-write issues.
///
/// If the wallet is already deployed (or the signature is plain EIP-1271/EOA),
/// we submit a single `transferWithAuthorization` transaction.
///
/// # Returns
/// A [`SettleResponse`] containing success flag and transaction hash.
///
/// # Errors
/// Propagates [`FacilitatorLocalError::ContractCall`] on deployment or transfer failures
/// and all prior validation errors.
pub async fn settle_authorization<P: MetaEvmProvider>(
    provider: &P,
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Result<SettleResponse, FacilitatorLocalError>
where
    FacilitatorLocalError: From<P::Error>,
{
    let (contract, payment, eip712_domain) =
        assert_valid_payment(provider.inner(), provider.chain(), payload, requirements)
            .await?;

    let signed_message = SignedMessage::extract(&payment, &eip712_domain)?;
    let payer = signed_message.address;
    let transaction_receipt_fut = match signed_message.signature {
        StructuredSignature::EIP6492 {
            factory,
            factory_calldata,
            inner,
            original: _,
        } => {
            let is_contract_deployed = is_contract_deployed(provider.inner(), &payer)
                .await?;
            let transfer_call = transferWithAuthorization_0(&contract, &payment, inner)
                .await?;
            if is_contract_deployed {
                // transferWithAuthorization with inner signature
                provider
                    .send_transaction(MetaTransaction {
                        to: transfer_call.tx.target(),
                        calldata: transfer_call.tx.calldata().clone(),
                        confirmations: 1,
                    })
                    .instrument(
                        tracing::info_span!("call_transferWithAuthorization_0",
                            from = %transfer_call.from,
                            to = %transfer_call.to,
                            value = %transfer_call.value,
                            valid_after = %transfer_call.valid_after,
                            valid_before = %transfer_call.valid_before,
                            nonce = %transfer_call.nonce,
                            signature = %transfer_call.signature,
                            token_contract = %transfer_call.contract_address,
                            sig_kind="EIP6492.deployed",
                            otel.kind = "client",
                        ),
                    )
            } else {
                // deploy the smart wallet, and transferWithAuthorization with inner signature
                let deployment_call = IMulticall3::Call3 {
                    allowFailure: true,
                    target: factory,
                    callData: factory_calldata,
                };
                let transfer_with_authorization_call = IMulticall3::Call3 {
                    allowFailure: false,
                    target: transfer_call.tx.target(),
                    callData: transfer_call.tx.calldata().clone(),
                };
                let aggregate_call = IMulticall3::aggregate3Call {
                    calls: vec![deployment_call, transfer_with_authorization_call],
                };
                provider
                    .send_transaction(MetaTransaction {
                        to: MULTICALL3_ADDRESS,
                        calldata: aggregate_call.abi_encode().into(),
                        confirmations: 1,
                    })
                    .instrument(
                        tracing::info_span!("call_transferWithAuthorization_0",
                            from = %transfer_call.from,
                            to = %transfer_call.to,
                            value = %transfer_call.value,
                            valid_after = %transfer_call.valid_after,
                            valid_before = %transfer_call.valid_before,
                            nonce = %transfer_call.nonce,
                            signature = %transfer_call.signature,
                            token_contract = %transfer_call.contract_address,
                            sig_kind="EIP6492.counterfactual",
                            otel.kind = "client",
                        ),
                    )
            }
        }
        StructuredSignature::EIP1271(eip1271_signature) => {
            let transfer_call = transferWithAuthorization_0(&contract, &payment, eip1271_signature)
                .await?;
            // transferWithAuthorization with eip1271 signature
            provider
                .send_transaction(MetaTransaction {
                    to: transfer_call.tx.target(),
                    calldata: transfer_call.tx.calldata().clone(),
                    confirmations: 1,
                })
                .instrument(
                    tracing::info_span!("call_transferWithAuthorization_0",
                        from = %transfer_call.from,
                        to = %transfer_call.to,
                        value = %transfer_call.value,
                        valid_after = %transfer_call.valid_after,
                        valid_before = %transfer_call.valid_before,
                        nonce = %transfer_call.nonce,
                        signature = %transfer_call.signature,
                        token_contract = %transfer_call.contract_address,
                        sig_kind="EIP1271",
                        otel.kind = "client",
                    ),
                )
        }
    };
    let receipt = transaction_receipt_fut.await.map_err(Into::into)?;
    let success = receipt.status();
    if success {
        tracing::event!(Level::INFO,
            status = "ok",
            tx = %receipt.transaction_hash,
            "transferWithAuthorization_0 succeeded"
        );
        Ok(SettleResponse {
            success: true,
            error_reason: None,
            payer: payment.from.into(),
            transaction: Some(TransactionHash::Evm(receipt.transaction_hash.0)),
            network: payload.network,
        })
    } else {
        tracing::event!(
            Level::WARN,
            status = "failed",
            tx = %receipt.transaction_hash,
            "transferWithAuthorization_0 failed"
        );
        Ok(SettleResponse {
            success: false,
            error_reason: Some(FacilitatorErrorReason::InvalidScheme),
            payer: payment.from.into(),
            transaction: Some(TransactionHash::Evm(receipt.transaction_hash.0)),
            network: payload.network,
        })
    }
}
