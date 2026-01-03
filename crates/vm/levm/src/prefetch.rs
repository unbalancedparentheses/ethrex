//! Speculative prefetching for EVM state access.
//!
//! This module implements prefetching based on ERC-20 pattern detection.
//! By analyzing transaction calldata, we can predict which storage slots
//! will be accessed and prefetch them before execution begins.

use bytes::Bytes;
use ethrex_common::types::{Transaction, TxKind};
use ethrex_common::{Address, H256};
use sha3::{Digest, Keccak256};

/// Convert TxKind to Option<Address>
fn tx_kind_to_address(kind: TxKind) -> Option<Address> {
    match kind {
        TxKind::Call(addr) => Some(addr),
        TxKind::Create => None,
    }
}

// ERC-20 function selectors
const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

// Standard ERC-20 storage slots
const BALANCE_SLOT: u8 = 0;
const ALLOWANCE_SLOT: u8 = 1;

/// Compute storage slot for balanceOf[addr] (mapping at slot 0)
fn balance_of_slot(addr: Address) -> H256 {
    let mut data = [0u8; 64];
    data[12..32].copy_from_slice(addr.as_bytes()); // address padded to 32 bytes
    data[63] = BALANCE_SLOT; // slot index
    H256::from_slice(&Keccak256::digest(data))
}

/// Compute storage slot for allowance[owner][spender] (nested mapping at slot 1)
fn allowance_slot(owner: Address, spender: Address) -> H256 {
    // First hash: keccak256(owner || slot_1)
    let mut data1 = [0u8; 64];
    data1[12..32].copy_from_slice(owner.as_bytes());
    data1[63] = ALLOWANCE_SLOT;
    let inner_slot = Keccak256::digest(data1);

    // Second hash: keccak256(spender || inner_slot)
    let mut data2 = [0u8; 64];
    data2[12..32].copy_from_slice(spender.as_bytes());
    data2[32..64].copy_from_slice(&inner_slot);
    H256::from_slice(&Keccak256::digest(data2))
}

/// Extract address from calldata at given offset (32-byte aligned, address in last 20 bytes)
fn extract_address(calldata: &[u8], offset: usize) -> Option<Address> {
    let end = offset.checked_add(32)?;
    if calldata.len() < end {
        return None;
    }
    // Address is last 20 bytes of 32-byte slot
    let start = offset.checked_add(12)?;
    Some(Address::from_slice(calldata.get(start..end)?))
}

/// Predict storage slots to prefetch based on ERC-20 function patterns.
/// Returns list of (contract_address, storage_slot) pairs to prefetch.
pub fn predict_erc20_slots(
    to: Option<Address>,
    sender: Address,
    calldata: &Bytes,
) -> Vec<(Address, H256)> {
    let Some(contract) = to else {
        return vec![]; // Contract creation, no prefetch
    };

    if calldata.len() < 4 {
        return vec![]; // No function selector
    }

    let Some(selector_slice) = calldata.get(0..4) else {
        return vec![];
    };
    let Ok(selector) = <[u8; 4]>::try_from(selector_slice) else {
        return vec![];
    };

    let mut slots = Vec::new();

    match selector {
        TRANSFER => {
            // transfer(address to, uint256 amount)
            // Accesses: balanceOf[sender], balanceOf[to]
            if let Some(to_addr) = extract_address(calldata, 4) {
                slots.push((contract, balance_of_slot(sender)));
                slots.push((contract, balance_of_slot(to_addr)));
            }
        }
        TRANSFER_FROM => {
            // transferFrom(address from, address to, uint256 amount)
            // Accesses: balanceOf[from], balanceOf[to], allowance[from][sender]
            if let (Some(from), Some(to_addr)) =
                (extract_address(calldata, 4), extract_address(calldata, 36))
            {
                slots.push((contract, balance_of_slot(from)));
                slots.push((contract, balance_of_slot(to_addr)));
                slots.push((contract, allowance_slot(from, sender)));
            }
        }
        APPROVE => {
            // approve(address spender, uint256 amount)
            // Accesses: allowance[sender][spender]
            if let Some(spender) = extract_address(calldata, 4) {
                slots.push((contract, allowance_slot(sender, spender)));
            }
        }
        BALANCE_OF => {
            // balanceOf(address)
            if let Some(addr) = extract_address(calldata, 4) {
                slots.push((contract, balance_of_slot(addr)));
            }
        }
        _ => {
            // Unknown function - no speculative prefetch
        }
    }

    slots
}

/// Collect all prefetch targets from a block's transactions.
///
/// Returns:
/// - `addresses`: All accounts to prefetch (senders, recipients, coinbase)
/// - `storage_slots`: All (address, slot) pairs to prefetch
pub fn collect_prefetch_targets(
    transactions: &[(&Transaction, Address)],
    coinbase: Address,
) -> (Vec<Address>, Vec<(Address, H256)>) {
    let mut addresses = Vec::with_capacity(transactions.len().saturating_mul(2).saturating_add(1));
    let mut storage_slots = Vec::new();

    addresses.push(coinbase);

    for (tx, sender) in transactions {
        // Always prefetch sender and recipient accounts
        addresses.push(*sender);
        let to_addr = tx_kind_to_address(tx.to());
        if let Some(to) = to_addr {
            addresses.push(to);
        }

        // Add access_list addresses and slots (only ~5% of blocks have these)
        for (addr, keys) in tx.access_list() {
            addresses.push(*addr);
            for key in keys {
                storage_slots.push((*addr, *key));
            }
        }

        // Speculative: ERC-20 pattern detection (~50% of transactions)
        let erc20_slots = predict_erc20_slots(to_addr, *sender, tx.data());
        storage_slots.extend(erc20_slots);
    }

    // Deduplicate addresses
    addresses.sort_unstable();
    addresses.dedup();

    (addresses, storage_slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_of_slot() {
        let addr = Address::from_low_u64_be(0x1234);
        let slot = balance_of_slot(addr);
        // Slot should be deterministic
        assert_eq!(slot, balance_of_slot(addr));
    }

    #[test]
    fn test_allowance_slot() {
        let owner = Address::from_low_u64_be(0x1234);
        let spender = Address::from_low_u64_be(0x5678);
        let slot = allowance_slot(owner, spender);
        // Slot should be deterministic
        assert_eq!(slot, allowance_slot(owner, spender));
        // Different owner/spender should give different slot
        assert_ne!(slot, allowance_slot(spender, owner));
    }

    #[test]
    fn test_extract_address() {
        let mut calldata = vec![0u8; 36];
        // Put address at offset 4 (after selector)
        let addr = Address::from_low_u64_be(0xdeadbeef);
        calldata[16..36].copy_from_slice(addr.as_bytes());

        let extracted = extract_address(&calldata, 4);
        assert_eq!(extracted, Some(addr));
    }

    #[test]
    fn test_predict_transfer_slots() {
        let sender = Address::from_low_u64_be(0x1111);
        let recipient = Address::from_low_u64_be(0x2222);
        let contract = Address::from_low_u64_be(0x3333);

        // Build transfer(address to, uint256 amount) calldata
        let mut calldata = vec![0u8; 68];
        calldata[0..4].copy_from_slice(&TRANSFER);
        calldata[16..36].copy_from_slice(recipient.as_bytes());
        // amount at offset 36 (not needed for slot prediction)

        let slots = predict_erc20_slots(Some(contract), sender, &Bytes::from(calldata));

        assert_eq!(slots.len(), 2);
        assert!(slots.contains(&(contract, balance_of_slot(sender))));
        assert!(slots.contains(&(contract, balance_of_slot(recipient))));
    }
}
