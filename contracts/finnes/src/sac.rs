//! SAC (Stellar Asset Contract) token movement for the shield / unshield
//! boundary (FIN-010).
//!
//! The shielded domain holds value as Poseidon commitments; crossing the
//! boundary moves the REAL underlying SAC token:
//!   - `shield`   pulls `depositor -> contract` (value enters the shielded set),
//!   - `unshield` pays `contract -> recipient`  (value leaves to the transparent
//!     layer).
//!
//! ## Resolving the token (invariant #11: no on-chain hashing)
//!
//! A note's `asset_id = Poseidon(sac_address)` is bound IN-CIRCUIT and proved a
//! member of `assets_root`. The contract cannot recompute that hash on-chain, so
//! it resolves the concrete SAC `Address` from an admin-registered mirror of the
//! assets registry (`state::get_asset_sac`). Accepting a caller-supplied SAC
//! address instead would let a depositor shield a worthless token while minting a
//! note labelled as a valuable `asset_id` (the on-chain half of invariant #18),
//! so the mapping MUST come from trusted admin state, never the caller.
//!
//! ## Amounts
//!
//! Note values are raw SAC units, 64-bit range-checked in-circuit, carried on the
//! wire as big-endian `Fr` scalars. SAC `transfer` takes an `i128`; the top 24
//! bytes of the scalar must therefore be zero (the value fits in `u64`), else the
//! public input is malformed.

use soroban_sdk::{token::TokenClient, Address, Env};

use crate::errors::Error;
use crate::state;
use crate::types::Scalar;

/// Decode a big-endian `Fr` scalar to an `i128` SAC amount.
///
/// The value is 64-bit range-checked in-circuit, so the high 24 bytes MUST be
/// zero; anything else is a malformed public input (we never silently truncate).
/// The result is non-negative and fits `i128` comfortably.
pub fn scalar_to_i128(amount: &Scalar) -> Result<i128, Error> {
    let b = amount.to_array();
    // High 24 bytes must be zero (value < 2^64).
    let mut i = 0;
    while i < 24 {
        if b[i] != 0 {
            return Err(Error::MalformedPublicInputs);
        }
        i += 1;
    }
    let mut lo = [0u8; 8];
    lo.copy_from_slice(&b[24..32]);
    Ok(u64::from_be_bytes(lo) as i128)
}

/// Pull `amount` of the SAC token bound to `asset_id` from `from` into the
/// contract (shield). Resolves the SAC via the admin registry; the token's own
/// `transfer` enforces `from`'s authorization.
pub fn pull_deposit(
    env: &Env,
    asset_id: &Scalar,
    from: &Address,
    amount: &Scalar,
) -> Result<(), Error> {
    let sac = state::get_asset_sac(env, asset_id).ok_or(Error::AssetNotRegistered)?;
    let amt = scalar_to_i128(amount)?;
    let contract = env.current_contract_address();
    TokenClient::new(env, &sac).transfer(from, &contract, &amt);
    Ok(())
}

/// Pay `amount` of the SAC token bound to `asset_id` from the contract to a
/// transparent `recipient` address (unshield). Resolves the SAC via the admin
/// registry.
pub fn pay_out(
    env: &Env,
    asset_id: &Scalar,
    recipient: &Address,
    amount: &Scalar,
) -> Result<(), Error> {
    let sac = state::get_asset_sac(env, asset_id).ok_or(Error::AssetNotRegistered)?;
    let amt = scalar_to_i128(amount)?;
    let contract = env.current_contract_address();
    TokenClient::new(env, &sac).transfer(&contract, recipient, &amt);
    Ok(())
}
