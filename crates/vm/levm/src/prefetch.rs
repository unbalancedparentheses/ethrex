//! Speculative prefetching for EVM state access.
//!
//! This module implements prefetching based on:
//! 1. ERC-20 pattern detection from calldata
//! 2. Bytecode analysis to find SLOAD patterns
//!
//! By analyzing transaction calldata and contract bytecode, we can predict
//! which storage slots will be accessed and prefetch them before execution begins.

use bytes::Bytes;
use ethrex_common::types::{Code, Transaction, TxKind};
use ethrex_common::{Address, H256};
use sha3::{Digest, Keccak256};

// EVM Opcodes for bytecode analysis
const OP_SLOAD: u8 = 0x54;
const OP_CALLER: u8 = 0x33;
const OP_ORIGIN: u8 = 0x32;
const OP_SHA3: u8 = 0x20;
const OP_PUSH0: u8 = 0x5F;
const OP_PUSH1: u8 = 0x60;
const OP_PUSH32: u8 = 0x7F;

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

// ============================================================================
// Bytecode Analysis for SLOAD Pattern Detection
// ============================================================================

/// Result of bytecode analysis for SLOAD patterns
#[derive(Debug, Default)]
pub struct BytecodeAnalysis {
    /// Direct constant storage slots accessed via PUSH + SLOAD
    pub constant_slots: Vec<H256>,
    /// Whether the contract accesses mapping[msg.sender] pattern
    pub uses_caller_mapping: bool,
    /// Whether the contract accesses mapping[tx.origin] pattern
    pub uses_origin_mapping: bool,
    /// Detected mapping base slots (for caller/origin patterns)
    pub mapping_base_slots: Vec<u8>,
}

/// Analyze contract bytecode to find SLOAD access patterns.
///
/// This performs a linear scan of the bytecode looking for:
/// 1. PUSH<n> followed by SLOAD - constant slot access
/// 2. CALLER ... SHA3 ... SLOAD - mapping[msg.sender] pattern
/// 3. ORIGIN ... SHA3 ... SLOAD - mapping[tx.origin] pattern
///
/// Returns analysis results that can be used to predict storage slots.
pub fn analyze_bytecode(code: &Code) -> BytecodeAnalysis {
    let bytecode = &code.bytecode;
    if bytecode.is_empty() {
        return BytecodeAnalysis::default();
    }

    let mut analysis = BytecodeAnalysis::default();
    let mut i = 0;
    let len = bytecode.len();

    // Track recent opcodes for pattern matching (simple sliding window)
    let mut saw_caller = false;
    let mut saw_origin = false;
    let mut saw_sha3 = false;
    let mut last_push_value: Option<H256> = None;
    let mut last_small_push: Option<u8> = None;

    while i < len {
        let op = bytecode[i];

        match op {
            OP_CALLER => {
                saw_caller = true;
                saw_origin = false;
                i += 1;
            }
            OP_ORIGIN => {
                saw_origin = true;
                saw_caller = false;
                i += 1;
            }
            OP_SHA3 => {
                saw_sha3 = true;
                i += 1;
            }
            OP_SLOAD => {
                // Check if preceded by a PUSH with constant value
                if let Some(slot) = last_push_value {
                    if !analysis.constant_slots.contains(&slot) {
                        analysis.constant_slots.push(slot);
                    }
                }

                // Check for mapping patterns
                if saw_sha3 {
                    if saw_caller {
                        analysis.uses_caller_mapping = true;
                        if let Some(base) = last_small_push {
                            if !analysis.mapping_base_slots.contains(&base) {
                                analysis.mapping_base_slots.push(base);
                            }
                        }
                    }
                    if saw_origin {
                        analysis.uses_origin_mapping = true;
                        if let Some(base) = last_small_push {
                            if !analysis.mapping_base_slots.contains(&base) {
                                analysis.mapping_base_slots.push(base);
                            }
                        }
                    }
                }

                // Reset tracking
                saw_caller = false;
                saw_origin = false;
                saw_sha3 = false;
                last_push_value = None;
                i += 1;
            }
            OP_PUSH0 => {
                last_push_value = Some(H256::zero());
                last_small_push = Some(0);
                i += 1;
            }
            op if (OP_PUSH1..=OP_PUSH32).contains(&op) => {
                let push_size = (op - OP_PUSH1 + 1) as usize;
                let data_end = i + 1 + push_size;

                if data_end <= len {
                    // Extract the pushed value
                    let mut slot_bytes = [0u8; 32];
                    let start = 32 - push_size;
                    slot_bytes[start..].copy_from_slice(&bytecode[i + 1..data_end]);
                    last_push_value = Some(H256::from(slot_bytes));

                    // Track small pushes for mapping base slot detection
                    if push_size == 1 {
                        last_small_push = Some(bytecode[i + 1]);
                    }
                }
                i = data_end;
            }
            _ => {
                // Other opcodes - don't reset CALLER/ORIGIN tracking
                // as the pattern may span multiple opcodes
                last_push_value = None;
                i += 1;
            }
        }

        // Limit analysis to first 4KB to avoid spending too much time on large contracts
        if i > 4096 {
            break;
        }
    }

    analysis
}

/// Compute storage slot for a mapping[address] at given base slot.
/// Uses standard Solidity storage layout: keccak256(address || base_slot)
fn mapping_slot_for_address(addr: Address, base_slot: u8) -> H256 {
    let mut data = [0u8; 64];
    data[12..32].copy_from_slice(addr.as_bytes()); // address padded to 32 bytes
    data[63] = base_slot; // slot index
    H256::from_slice(&Keccak256::digest(data))
}

/// Predict storage slots based on bytecode analysis.
///
/// Uses the bytecode analysis to predict which slots will be accessed,
/// given the transaction sender and origin.
pub fn predict_slots_from_bytecode(
    contract: Address,
    analysis: &BytecodeAnalysis,
    sender: Address,
    origin: Address,
) -> Vec<(Address, H256)> {
    let mut slots = Vec::new();

    // Add all constant slots
    for slot in &analysis.constant_slots {
        slots.push((contract, *slot));
    }

    // Add mapping slots for caller/origin
    for &base_slot in &analysis.mapping_base_slots {
        if analysis.uses_caller_mapping {
            slots.push((contract, mapping_slot_for_address(sender, base_slot)));
        }
        if analysis.uses_origin_mapping {
            slots.push((contract, mapping_slot_for_address(origin, base_slot)));
        }
    }

    // If we detected caller/origin mapping but no specific base slots,
    // try common slots 0, 1, 2 (balances, allowances, etc.)
    if (analysis.uses_caller_mapping || analysis.uses_origin_mapping)
        && analysis.mapping_base_slots.is_empty()
    {
        for base in 0..3u8 {
            if analysis.uses_caller_mapping {
                slots.push((contract, mapping_slot_for_address(sender, base)));
            }
            if analysis.uses_origin_mapping {
                slots.push((contract, mapping_slot_for_address(origin, base)));
            }
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

    // Bytecode analysis tests

    #[test]
    fn test_analyze_bytecode_constant_sload() {
        // Bytecode: PUSH1 0x05 SLOAD
        let bytecode = vec![OP_PUSH1, 0x05, OP_SLOAD];
        let code = Code::from_bytecode(Bytes::from(bytecode));
        let analysis = analyze_bytecode(&code);

        assert_eq!(analysis.constant_slots.len(), 1);
        let expected_slot = H256::from_low_u64_be(5);
        assert_eq!(analysis.constant_slots[0], expected_slot);
    }

    #[test]
    fn test_analyze_bytecode_caller_mapping() {
        // Simplified bytecode simulating: CALLER PUSH1 0x00 ... SHA3 SLOAD
        let bytecode = vec![
            OP_CALLER,       // Get msg.sender
            OP_PUSH1, 0x00,  // Push mapping slot 0
            OP_SHA3,         // Hash for mapping lookup
            OP_SLOAD,        // Load from storage
        ];
        let code = Code::from_bytecode(Bytes::from(bytecode));
        let analysis = analyze_bytecode(&code);

        assert!(analysis.uses_caller_mapping);
        assert!(!analysis.uses_origin_mapping);
    }

    #[test]
    fn test_analyze_bytecode_origin_mapping() {
        // Simplified bytecode simulating: ORIGIN PUSH1 0x01 ... SHA3 SLOAD
        let bytecode = vec![
            OP_ORIGIN,       // Get tx.origin
            OP_PUSH1, 0x01,  // Push mapping slot 1
            OP_SHA3,         // Hash for mapping lookup
            OP_SLOAD,        // Load from storage
        ];
        let code = Code::from_bytecode(Bytes::from(bytecode));
        let analysis = analyze_bytecode(&code);

        assert!(!analysis.uses_caller_mapping);
        assert!(analysis.uses_origin_mapping);
    }

    #[test]
    fn test_predict_slots_from_bytecode() {
        let contract = Address::from_low_u64_be(0x1234);
        let sender = Address::from_low_u64_be(0xAABB);
        let origin = Address::from_low_u64_be(0xCCDD);

        let analysis = BytecodeAnalysis {
            constant_slots: vec![H256::from_low_u64_be(5)],
            uses_caller_mapping: true,
            uses_origin_mapping: false,
            mapping_base_slots: vec![0],
        };

        let slots = predict_slots_from_bytecode(contract, &analysis, sender, origin);

        // Should have constant slot + mapping[sender] at slot 0
        assert_eq!(slots.len(), 2);
        assert!(slots.contains(&(contract, H256::from_low_u64_be(5))));
        assert!(slots.contains(&(contract, mapping_slot_for_address(sender, 0))));
    }

    #[test]
    fn test_mapping_slot_computation() {
        let addr = Address::from_low_u64_be(0x1234);
        let slot = mapping_slot_for_address(addr, 0);

        // Should be deterministic
        assert_eq!(slot, mapping_slot_for_address(addr, 0));

        // Different base slot should give different result
        assert_ne!(slot, mapping_slot_for_address(addr, 1));

        // Different address should give different result
        let addr2 = Address::from_low_u64_be(0x5678);
        assert_ne!(slot, mapping_slot_for_address(addr2, 0));
    }
}
