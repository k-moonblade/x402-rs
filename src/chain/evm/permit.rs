//! EIP-2612 permit + transferFrom implementation for EVM chains.
//!
//! This module handles verification and settlement of payments using the EIP-2612
//! permit standard, which allows gasless token approvals via off-chain signatures.
//!
//! The settlement flow batches `permit()` and `transferFrom()` into a single
//! atomic transaction using Multicall3 to ensure both operations succeed or fail together.

use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{MULTICALL3_ADDRESS, Provider};
use alloy::providers::bindings::IMulticall3;
use alloy::sol_types::SolCall;
use tracing::{Instrument, instrument};

use crate::chain::evm::{IERC20Permit, MetaEvmProvider, MetaTransaction};
use crate::chain::FacilitatorLocalError;
use crate::network::Network;
use crate::timestamp::UnixTimestamp;
use crate::types::{
    EvmSignature, ExactEvmPermitPayload, FacilitatorErrorReason,
    SettleResponse, TransactionHash, VerifyResponse,
};

/// Extract v, r, s components from a 65-byte ECDSA signature.
///
/// Normalizes v to the legacy format (27 or 28) expected by EIP-2612 permit().
/// Alloy signatures use v = 0 or 1, but permit() requires v = 27 or 28.
///
/// # Errors
/// Returns [`FacilitatorLocalError::InvalidSignature`] if the signature is not exactly 65 bytes.
fn extract_vrs_from_signature(
    signature: &EvmSignature,
) -> Result<(u8, FixedBytes<32>, FixedBytes<32>), FacilitatorLocalError> {
    if signature.0.len() != 65 {
        return Err(FacilitatorLocalError::InvalidSignature(
            alloy::primitives::Address::ZERO.into(),
            format!("Signature must be 65 bytes, got {}", signature.0.len()),
        ));
    }
    let r = FixedBytes::<32>::from_slice(&signature.0[0..32]);
    let s = FixedBytes::<32>::from_slice(&signature.0[32..64]);
    let v_raw = signature.0[64];
    let mut v = v_raw;

    // Normalize v to legacy format (27 or 28) for EIP-2612 permit()
    if v < 27 {
        v += 27;
        tracing::debug!(v_raw = %v_raw, v_normalized = %v, "Normalized v value for permit()");
    }

    Ok((v, r, s))
}

/// Construct the EIP-712 digest for an EIP-2612 Permit message.
///
/// This computes the hash that should have been signed by the owner.
fn construct_permit_digest(
    domain_separator: FixedBytes<32>,
    owner: Address,
    spender: Address,
    value: U256,
    nonce: U256,
    deadline: U256,
) -> FixedBytes<32> {
    use alloy::primitives::keccak256;

    // PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
    let permit_typehash = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // Encode the struct hash (addresses are left-padded per EVM ABI encoding)
    let struct_hash = keccak256(
        [
            permit_typehash.as_slice(),
            &[0u8; 12], // pad address to 32 bytes (left-padding)
            owner.as_slice(),
            &[0u8; 12], // pad address to 32 bytes (left-padding)
            spender.as_slice(),
            &value.to_be_bytes::<32>(),
            &nonce.to_be_bytes::<32>(),
            &deadline.to_be_bytes::<32>(),
        ]
        .concat(),
    );

    // Construct the final digest: keccak256("\x19\x01" || domainSeparator || structHash)
    keccak256(
        [
            &[0x19, 0x01],
            domain_separator.as_slice(),
            struct_hash.as_slice(),
        ]
        .concat(),
    )
}

/// Verify an EIP-712 signature and recover the signer address.
///
/// # Errors
/// Returns [`FacilitatorLocalError::InvalidSignature`] if signature recovery fails.
fn verify_eip712_signature(
    digest: &FixedBytes<32>,
    signature: &EvmSignature,
) -> Result<Address, FacilitatorLocalError> {
    use alloy::primitives::Signature;

    let sig = Signature::try_from(signature.0.as_slice()).map_err(|e| {
        FacilitatorLocalError::InvalidSignature(
            alloy::primitives::Address::ZERO.into(),
            format!("Failed to parse signature: {e}"),
        )
    })?;

    sig.recover_address_from_prehash(digest).map_err(|e| {
        FacilitatorLocalError::InvalidSignature(
            alloy::primitives::Address::ZERO.into(),
            format!("Failed to recover address: {e}"),
        )
    })
}

/// Verify an EIP-2612 permit payment payload.
///
/// This function performs off-chain verification by checking:
/// 1. Deadline hasn't passed
/// 2. Nonce matches current on-chain nonce
/// 3. Owner has sufficient balance
/// 4. EIP-712 signature is valid and signed by owner
///
/// # Errors
/// Returns [`FacilitatorLocalError`] if any validation fails.
#[instrument(skip(provider, payment), err, fields(
    owner = %payment.owner,
    spender = %payment.spender,
    value = %payment.value,
    token = %payment.token,
))]
pub async fn verify_permit<P: Provider>(
    provider: &P,
    payment: &ExactEvmPermitPayload,
) -> Result<VerifyResponse, FacilitatorLocalError> {
    let token = IERC20Permit::new(payment.token.0, provider);
    let owner = payment.owner.0;
    let value: U256 = payment.value.into();

    tracing::info!(
        owner = %owner,
        spender = %payment.spender.0,
        token = %payment.token.0,
        value = %value,
        deadline = %payment.deadline,
        nonce = %payment.nonce,
        "Starting permit verification"
    );

    // Use multicall to batch read operations (gas-free simulation)
    let (nonce_result, balance_result, domain_result) = provider
        .multicall()
        .add(token.nonces(owner))
        .add(token.balanceOf(owner))
        .add(token.DOMAIN_SEPARATOR())
        .aggregate3()
        .instrument(tracing::info_span!("verify_permit_multicall",
            owner = %owner,
            token = %payment.token.0,
            otel.kind = "client",
        ))
        .await
        .map_err(|e| {
            tracing::error!(
                owner = %owner,
                token = %payment.token.0,
                error = %e,
                "Multicall failed during permit verification"
            );
            FacilitatorLocalError::ContractCall(format!("{e:?}"))
        })?;

    let nonce = nonce_result
        .map_err(|e| {
            tracing::error!(owner = %owner, error = %e, "Failed to get nonce");
            FacilitatorLocalError::ContractCall(format!("nonces: {e}"))
        })?;
    let balance = balance_result
        .map_err(|e| {
            tracing::error!(owner = %owner, error = %e, "Failed to get balance");
            FacilitatorLocalError::ContractCall(format!("balanceOf: {e}"))
        })?;
    let domain_separator = domain_result
        .map_err(|e| {
            tracing::error!(token = %payment.token.0, error = %e, "Failed to get DOMAIN_SEPARATOR");
            FacilitatorLocalError::ContractCall(format!("DOMAIN_SEPARATOR: {e}"))
        })?;

    tracing::info!(
        owner = %owner,
        on_chain_nonce = %nonce,
        payment_nonce = %payment.nonce,
        balance = %balance,
        required_value = %value,
        domain_separator = %domain_separator,
        "Fetched on-chain state for permit verification"
    );

    // 1. Check nonce
    if payment.nonce != nonce {
        tracing::error!(
            owner = %owner,
            on_chain_nonce = %nonce,
            payment_nonce = %payment.nonce,
            "Nonce mismatch"
        );
        return Err(FacilitatorLocalError::InvalidNonce(
            payment.owner.into(),
            format!("Expected nonce {}, got {}", nonce, payment.nonce),
        ));
    }
    tracing::info!(owner = %owner, nonce = %nonce, "✓ Nonce check passed");

    // 2. Check balance
    if balance < value {
        tracing::error!(
            owner = %owner,
            balance = %balance,
            required = %value,
            "Insufficient balance"
        );
        return Err(FacilitatorLocalError::InsufficientFunds(
            payment.owner.into(),
        ));
    }
    tracing::info!(owner = %owner, balance = %balance, required = %value, "✓ Balance check passed");

    // 3. Check deadline
    let current_time = UnixTimestamp::try_now().map_err(FacilitatorLocalError::ClockError)?;
    if current_time > payment.deadline {
        tracing::error!(
            owner = %owner,
            current_time = %current_time,
            deadline = %payment.deadline,
            "Permit expired"
        );
        return Err(FacilitatorLocalError::InvalidTiming(
            payment.owner.into(),
            format!(
                "Permit expired: current time {} > deadline {}",
                current_time, payment.deadline
            ),
        ));
    }
    tracing::info!(
        owner = %owner,
        current_time = %current_time,
        deadline = %payment.deadline,
        "✓ Deadline check passed"
    );

    // 4. Verify EIP-712 signature
    let digest = construct_permit_digest(
        domain_separator,
        owner,
        payment.spender.0,
        value,
        payment.nonce,
        payment.deadline.into(),
    );

    tracing::info!(
        owner = %owner,
        digest = %digest,
        "Constructed EIP-712 permit digest"
    );

    let recovered = verify_eip712_signature(&digest, &payment.signature)?;
    if recovered != owner {
        tracing::error!(
            owner = %owner,
            recovered = %recovered,
            "Signature verification failed: recovered address does not match owner"
        );
        return Err(FacilitatorLocalError::InvalidSignature(
            payment.owner.into(),
            format!("Expected owner {}, recovered {}", owner, recovered),
        ));
    }
    tracing::info!(owner = %owner, recovered = %recovered, "✓ Signature verification passed");

    tracing::info!(
        owner = %owner,
        spender = %payment.spender.0,
        value = %value,
        token = %payment.token.0,
        "✅ Permit verification succeeded - all checks passed"
    );

    Ok(VerifyResponse::valid(payment.owner.into()))
}

/// Settle an EIP-2612 permit payment using Multicall3 for atomicity.
///
/// This function batches `permit()` and `transferFrom()` into a single atomic transaction:
/// 1. Calls permit(owner, spender=MULTICALL3, value, deadline, v, r, s) to approve Multicall3
/// 2. Calls transferFrom(owner, recipient, value) to move tokens to the final recipient
///
/// Both calls execute atomically via Multicall3 - if either fails, the entire transaction reverts.
///
/// **Important**: The client must sign the permit with MULTICALL3_ADDRESS as the spender,
/// not the facilitator address, because Multicall3 is the contract that executes transferFrom().
///
/// # Errors
/// Returns [`FacilitatorLocalError`] if signature extraction or transaction submission fails.
#[instrument(skip(provider, payment, network), err, fields(
    owner = %payment.owner,
    spender = %payment.spender,
    payee = %payment.to,
    value = %payment.value,
    token = %payment.token,
))]
pub async fn settle_permit<P: MetaEvmProvider>(
    provider: &P,
    payment: &ExactEvmPermitPayload,
    network: Network,
) -> Result<SettleResponse, FacilitatorLocalError>
where
    FacilitatorLocalError: From<P::Error>,
{
    let token = IERC20Permit::new(payment.token.0, provider.inner());
    let owner = payment.owner.0;
    let spender = payment.spender.0;
    let value: U256 = payment.value.into();
    let deadline: U256 = payment.deadline.into();

    // Extract v, r, s from signature
    let (v, r, s) = extract_vrs_from_signature(&payment.signature)?;

    tracing::info!(
        owner = %owner,
        spender = %spender,
        recipient = %payment.to.0,
        value = %value,
        deadline = %deadline,
        v = %v,
        "Building multicall: permit(spender=Multicall3) + transferFrom(to=recipient)"
    );

    // Build Call 1: permit()
    let permit_call = token.permit(owner, spender, value, deadline, v, r, s);

    let permit_multicall = IMulticall3::Call3 {
        allowFailure: false, // MUST succeed
        target: payment.token.0,
        callData: permit_call.calldata().clone(),
    };

    // Build Call 2: transferFrom()
    let transfer_call = token.transferFrom(owner, payment.to.0, value);

    let transfer_multicall = IMulticall3::Call3 {
        allowFailure: false, // MUST succeed
        target: payment.token.0,
        callData: transfer_call.calldata().clone(),
    };

    // Batch both calls using Multicall3
    let aggregate_call = IMulticall3::aggregate3Call {
        calls: vec![permit_multicall, transfer_multicall],
    };

    // Send single transaction to Multicall3
    let receipt = provider
        .send_transaction(MetaTransaction {
            to: MULTICALL3_ADDRESS,
            calldata: aggregate_call.abi_encode().into(),
            confirmations: 1,
        })
        .instrument(tracing::info_span!("settle_permit_multicall",
            owner = %owner,
            spender = %spender,
            payee = %payment.to.0,
            value = %value,
            token = %payment.token.0,
            otel.kind = "client",
        ))
        .await
        .map_err(Into::into)?;

    // Check transaction status
    let success = receipt.status();

    if success {
        tracing::info!(
            status = "ok",
            tx = %receipt.transaction_hash,
            "Permit + transferFrom succeeded atomically"
        );
        Ok(SettleResponse {
            success: true,
            error_reason: None,
            payer: payment.owner.into(),
            transaction: Some(TransactionHash::Evm(receipt.transaction_hash.0)),
            network,
        })
    } else {
        tracing::error!(
            status = "failed",
            tx = %receipt.transaction_hash,
            "Permit + transferFrom failed"
        );
        Ok(SettleResponse {
            success: false,
            error_reason: Some(FacilitatorErrorReason::InvalidScheme),
            payer: payment.owner.into(),
            transaction: Some(TransactionHash::Evm(receipt.transaction_hash.0)),
            network,
        })
    }
}
