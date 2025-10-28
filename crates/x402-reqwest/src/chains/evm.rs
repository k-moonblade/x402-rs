use crate::X402PaymentsError;
use crate::chains::{IntoSenderWallet, SenderWallet};
use alloy::network::Ethereum;
use alloy::primitives::{FixedBytes, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolStruct, eip712_domain};
use async_trait::async_trait;
use rand::{Rng, rng};
use std::sync::Arc;
use x402_rs::chain::evm::{EvmChain, IERC20Permit};
use x402_rs::network::{Network, NetworkFamily};
use x402_rs::timestamp::UnixTimestamp;
use x402_rs::types::{
    EvmSignature, ExactEvmPayload, ExactEvmPayloadAuthorization, ExactEvmPermitPayload,
    ExactPaymentPayload, HexEncodedNonce, PaymentPayload, PaymentRequirements, Scheme,
    TransferWithAuthorization,
};

#[derive(Clone)]
pub struct EvmSenderWallet {
    signer: Arc<dyn Signer + Send + Sync>,
    provider: Option<Arc<DynProvider<Ethereum>>>,
}

impl EvmSenderWallet {
    pub fn new(signer: impl Signer + Send + Sync + 'static) -> Self {
        Self {
            signer: Arc::new(signer),
            provider: None,
        }
    }

    pub fn with_provider<P>(
        signer: impl Signer + Send + Sync + 'static,
        provider: P,
    ) -> Self
    where
        P: Provider + 'static,
    {
        Self {
            signer: Arc::new(signer),
            provider: Some(Arc::new(DynProvider::new(provider))),
        }
    }
}

impl<S> From<S> for EvmSenderWallet
where
    S: Signer + Send + Sync + 'static,
{
    fn from(signer: S) -> Self {
        Self::new(signer)
    }
}

impl IntoSenderWallet for PrivateKeySigner {
    fn into_sender_wallet(self) -> Arc<dyn SenderWallet> {
        Arc::new(EvmSenderWallet::new(self))
    }
}

impl IntoSenderWallet for EvmSenderWallet {
    fn into_sender_wallet(self) -> Arc<dyn SenderWallet> {
        Arc::new(self)
    }
}

impl EvmSenderWallet {
    async fn create_permit_payload(
        &self,
        selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError> {
        let provider = self.provider.as_ref().ok_or_else(|| {
            X402PaymentsError::SigningError(
                "RPC provider required for permit-based payments. Use EvmSenderWallet::with_provider()".to_string()
            )
        })?;

        let network = selected.network;
        let _evm_chain: EvmChain = network
            .try_into()
            .map_err(|e| X402PaymentsError::SigningError(format!("{e:?}")))?;

        let token_address: alloy::primitives::Address = selected.asset
            .try_into()
            .map_err(X402PaymentsError::InvalidEVMAddress)?;
        let token = IERC20Permit::new(token_address, Arc::clone(provider));
        let owner = self.signer.address();

        // Spender must be Multicall3 since it will call transferFrom in the settlement multicall
        let spender: alloy::primitives::Address = alloy::providers::MULTICALL3_ADDRESS;

        // Payment recipient (where tokens will be transferred to)
        let recipient: alloy::primitives::Address = selected
            .pay_to
            .clone()
            .try_into()
            .map_err(X402PaymentsError::InvalidEVMAddress)?;

        // Fetch nonce from chain
        let nonce: U256 = token
            .nonces(owner)
            .call()
            .await
            .map_err(|e| {
                X402PaymentsError::SigningError(format!(
                    "Failed to fetch nonce for permit signature. Token {} on network {} does not support EIP-2612 permit. \
                    The token must implement the permit() function for gasless approvals. Error: {e:?}",
                    token_address, network
                ))
            })?;

        let now = UnixTimestamp::try_now().map_err(X402PaymentsError::ClockError)?;
        let deadline = now + selected.max_timeout_seconds;
        let value: U256 = selected.max_amount_required.into();

        // Get domain separator for EIP-712
        let domain_separator = token
            .DOMAIN_SEPARATOR()
            .call()
            .await
            .map_err(|e| X402PaymentsError::SigningError(format!("Failed to fetch DOMAIN_SEPARATOR: {e:?}")))?;

        // Construct EIP-712 digest for permit
        let permit_typehash = alloy::primitives::keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
        let struct_hash = alloy::primitives::keccak256(
            [
                permit_typehash.as_slice(),
                &[0u8; 12], // pad owner to 32 bytes
                owner.as_slice(),
                &[0u8; 12], // pad spender to 32 bytes
                spender.as_slice(),
                &value.to_be_bytes::<32>(),
                &nonce.to_be_bytes::<32>(),
                &U256::from(deadline.seconds_since_epoch()).to_be_bytes::<32>(),
            ]
            .concat(),
        );

        let digest = alloy::primitives::keccak256(
            [
                &[0x19, 0x01],
                domain_separator.as_slice(),
                struct_hash.as_slice(),
            ]
            .concat(),
        );

        // Sign the digest
        let signature = self
            .signer
            .sign_hash(&digest)
            .await
            .map_err(|e| X402PaymentsError::SigningError(format!("{e:?}")))?;

        #[cfg(feature = "telemetry")]
        tracing::debug!(
            owner = %owner,
            spender = %spender,
            recipient = %recipient,
            value = %value,
            nonce = %nonce,
            deadline = %deadline,
            "Constructed permit payload (spender=Multicall3, recipient=pay_to)"
        );

        let payment_payload = PaymentPayload {
            x402_version: x402_rs::types::X402Version::V1,
            scheme: Scheme::Exact,
            network,
            payload: ExactPaymentPayload::EvmPermit(ExactEvmPermitPayload {
                owner: owner.into(),
                spender: spender.into(), // Multicall3 address (needs approval for transferFrom)
                value: selected.max_amount_required,
                nonce,
                deadline,
                signature: EvmSignature::from(signature.as_bytes()),
                token: token_address.into(),
                to: recipient.into(), // Final recipient of the tokens
            }),
        };
        Ok(payment_payload)
    }

    async fn create_authorization_payload(
        &self,
        selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError> {
        let (name, version) = match selected.extra {
            None => (None, None),
            Some(extra) => {
                let name = extra
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned);
                let version = extra
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned);
                (name, version)
            }
        };
        let network = selected.network;
        let evm_chain: EvmChain = network
            .try_into()
            .map_err(|e| X402PaymentsError::SigningError(format!("{e:?}")))?;
        let chain_id = evm_chain.chain_id;
        let domain = eip712_domain! {
            name: name.unwrap_or("".to_string()),
            version: version.unwrap_or("".to_string()),
            chain_id: chain_id,
            verifying_contract: selected.asset.try_into().map_err(X402PaymentsError::InvalidEVMAddress)?,
        };
        let now = UnixTimestamp::try_now().map_err(X402PaymentsError::ClockError)?;
        let valid_after = UnixTimestamp(now.seconds_since_epoch() - 10 * 60); // 10 mins before
        let valid_before = now + selected.max_timeout_seconds;
        let nonce: [u8; 32] = rng().random();
        let authorization = ExactEvmPayloadAuthorization {
            from: self.signer.address().into(),
            to: selected
                .pay_to
                .try_into()
                .map_err(X402PaymentsError::InvalidEVMAddress)?,
            value: selected.max_amount_required,
            valid_after,
            valid_before,
            nonce: HexEncodedNonce(nonce),
        };
        #[cfg(feature = "telemetry")]
        tracing::debug!(?authorization, "Constructed authorization payload");
        let transfer_with_authorization = TransferWithAuthorization {
            from: authorization.from.into(),
            to: authorization.to.into(),
            value: authorization.value.into(),
            validAfter: authorization.valid_after.into(),
            validBefore: authorization.valid_before.into(),
            nonce: FixedBytes(nonce),
        };
        let eip712_hash = transfer_with_authorization.eip712_signing_hash(&domain);
        let signature = self
            .signer
            .sign_hash(&eip712_hash)
            .await
            .map_err(|e| X402PaymentsError::SigningError(format!("{e:?}")))?;
        #[cfg(feature = "telemetry")]
        tracing::debug!(?signature, "Signature obtained");
        let payment_payload = PaymentPayload {
            x402_version: x402_rs::types::X402Version::V1,
            scheme: Scheme::Exact,
            network,
            payload: ExactPaymentPayload::Evm(ExactEvmPayload {
                signature: EvmSignature::from(signature.as_bytes()),
                authorization,
            }),
        };
        Ok(payment_payload)
    }
}

#[async_trait]
impl SenderWallet for EvmSenderWallet {
    fn can_handle(&self, requirements: &PaymentRequirements) -> bool {
        let network = requirements.network;
        let network_family: NetworkFamily = network.into();
        match network_family {
            NetworkFamily::Evm => true,
            NetworkFamily::Solana => false,
        }
    }

    async fn payment_payload(
        &self,
        selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError> {
        let network = selected.network;

        // BSC network requires permit-based payments
        let use_permit = matches!(network, Network::Bsc);

        if use_permit {
            self.create_permit_payload(selected).await
        } else {
            self.create_authorization_payload(selected).await
        }
    }
}
