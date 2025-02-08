use std::{
    fs::{self, File}, io::{Read, Write}, ops::Add, path::Path
};

use alloy::{hex::FromHex, primitives::{keccak256, Address, Bytes, FixedBytes, U160, U256}};

pub mod address_verifier;
pub mod bytecode_verifier;
pub mod fee_param_verifier;
pub mod network_verifier;
pub mod selector_verifier;
pub mod facet_cut_set;

pub async fn get_contents_from_github(commit: &str, repo: &str, file_path: &str) -> String {
    let url = format!(
        "https://raw.githubusercontent.com/{repo}/{}/{file_path}",
        commit
    );

    let cache_path = Path::new("cache");
    fs::create_dir_all(cache_path).expect("Failed to create cache directory");

    let cache_file_path = cache_path.join(format!(
        "{}-{}.json",
        Path::new(file_path).file_name().unwrap().to_str().unwrap(),
        commit
    ));

    if !cache_file_path.exists() {
        let response = reqwest::get(url).await.unwrap();

        let mut file = File::create(cache_file_path.clone()).expect("Failed to create cache file");
        let data = response.bytes().await.unwrap();
        file.write_all(&data).unwrap();
    }

    let data = fs::read_to_string(&cache_file_path).expect("Failed to read cache file");
    return data;
}

pub fn compute_create2_address_zk(
    sender: Address,
    salt: FixedBytes<32>,
    bytecode_hash: FixedBytes<32>,
    constructor_input_hash: FixedBytes<32>,
) -> Address {
    let mut address_payload = vec![];

    address_payload.extend_from_slice(&keccak256("zksyncCreate2").as_slice());
    address_payload.extend_from_slice(&[0u8; 12]);
    address_payload.extend_from_slice(sender.as_slice());

    // Extract salt
    address_payload.extend_from_slice(salt.as_slice());
    // And hash the rest.
    address_payload.extend_from_slice(bytecode_hash.as_slice());

    address_payload.extend_from_slice(constructor_input_hash.as_slice());

    // compute create2 address
    Address::from_slice(&keccak256(address_payload).0[12..])
}

pub fn compute_create2_address_evm(
    sender: Address,
    salt: FixedBytes<32>,
    bytecode_hash: FixedBytes<32>,
) -> Address {
    let mut address_payload = vec![];
    address_payload.extend_from_slice(&[0xff as u8]);
    address_payload.extend_from_slice(sender.as_slice());

    // Extract salt
    address_payload.extend_from_slice(salt.as_slice());
    // And hash the rest.
    address_payload.extend_from_slice(bytecode_hash.as_slice());

    // compute create2 address
    Address::from_slice(&keccak256(address_payload).0[12..])
}

pub fn compute_hash_with_arguments(
    input: &Bytes,
    num_arguments: usize,
) -> Option<FixedBytes<32>> {
    if input.len() < (num_arguments + 2) * 32 {
        None
    } else {
        Some(keccak256(&input[0..input.len() - 32 * num_arguments]))
    }
}

pub fn apply_l2_to_l1_alias(addr: Address) -> Address {
    let offset = U160::from_str_radix("1111000000000000000000000000000000001111", 16).unwrap();

    let addr_as_u256 = U160::from_be_bytes(addr.0.0);

    let result = offset + addr_as_u256;

    Address(FixedBytes::<20>(result.to_be_bytes()))
}

pub fn unapply_l2_to_l1_alias(addr: Address) -> Address {
    let offset = U160::from_str_radix("1111000000000000000000000000000000001111", 16).unwrap();

    let addr_as_u256 = U160::from_be_bytes(addr.0.0);

    let result = addr_as_u256 - offset;

    Address(FixedBytes::<20>(result.to_be_bytes()))
}
