mod pgen;

use circuits::passport::{LEN_DATE, LEN_DG1, LEN_PNUM_HASH, PassportRelation};
use hex_literal::hex;
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use std::env;

const PNUM_HASH: [u8; LEN_PNUM_HASH] =
    hex!("4f6c85278ea16056648653fddc18983f3158c0fd963108c2c0355861555f1e0e");
const TODAYS_DATE: [u8; LEN_DATE] = *b"20251202";

pub const ARG_PUBKEY_EXP: [u8; 3] = hex!("010001");
pub const ARG_PUBKEY_MOD: [u8; 384] = hex!(
    "c9a6105edffbf21e91ce42dc29b024ca8fb2c0c28ba8fcc0710d8275943a058494cb785caa1735f72d23364e1c5580501fbaea283458c47363fcdf475b9f86db803c812d87921142c38eb199b4787a0957368e8d454794c16ca182431e373ab853e5f21d7766b86614e300d4853329aa1bf88082d10f5c095bcf2fc60b371f2a8f37e1bbc84cefd98926b7f499914dd5af7977b9a1113afeb89bf46d1162bf5bf7aa9a47c5a9b22979c1fafd9de434395cef7e46ea13603da949582713e9347df8e151079c108860854486ab31a51186eed42caaf63be699452e113cd5865917f71c0fd352faf2f6cf69b28a395102ad0e471828e08276413efd47017d1bc512b4b557b4fb0386881542c8ef4f75cfd4ac787ff345c886027d54ca0d23894ffcf9cc218ce7e0026e1b304c038b1ab12052e9ef217d3a020ec85141e0948a97d7b87b901edb46a8f6d27b7c52c2eaa27bb5ca32df9affd73bba4134c2d9c64d41e1cef44b5d35f69db5e31df0c871386adff87b934b5923adf5ebcb469140c49d"
);

pub const ITA_PUBKEY_EXP: [u8; 3] = hex!("010001");
pub const ITA_PUBKEY_MOD: [u8; 384] = hex!(
    "caa6105edffbf21e91ce42dc29b024ca8fb2c0c28ba8fcc0710d8275943a058494cb785caa1735f72d23364e1c5580501fbaea283458c47363fcdf475b9f86db803c812d87921142c38eb199b4787a0957368e8d454794c16ca182431e373ab853e5f21d7766b86614e300d4853329aa1bf88082d10f5c095bcf2fc60b371f2a8f37e1bbc84cefd98926b7f499914dd5af7977b9a1113afeb89bf46d1162bf5bf7aa9a47c5a9b22979c1fafd9de434395cef7e46ea13603da949582713e9347df8e151079c108860854486ab31a51186eed42caaf63be699452e113cd5865917f71c0fd352faf2f6cf69b28a395102ad0e471828e08276413efd47017d1bc512b4b557b4fb0386881542c8ef4f75cfd4ac787ff345c886027d54ca0d23894ffcf9cc218ce7e0026e1b304c038b1ab12052e9ef217d3a020ec85141e0948a97d7b87b901edb46a8f6d27b7c52c2eaa27bb5ca32df9affd73bba4134c2d9c64d41e1cef44b5d35f69db5e31df0c871386adff87b934b5923adf5ebcb469140c49d"
);

pub static EFSOD: Lazy<[u8; 1912]> = Lazy::new(|| {
    let hex_str = env::var("EFSOD_HEX").expect("EFSOD_HEX env var not set");
    let bytes = hex::decode(&hex_str).expect("EFSOD_HEX is not valid hex");

    bytes
        .try_into()
        .expect("EFSOD_HEX has wrong length; expected 1912 bytes")
});

pub static DG1: Lazy<[u8; LEN_DG1]> = Lazy::new(|| {
    let hex_str = env::var("DG1_HEX").expect("DG1_HEX env var not set");
    let bytes = hex::decode(&hex_str).expect("DG1_HEX is not valid hex");

    bytes
        .try_into()
        .expect("DG1_HEX has wrong length; expected LEN_DG1 bytes")
});

fn main() {
    // Public inputs

    dotenvy::dotenv().ok();
    let pk_arg = (
        *b"ARG",
        0,
        BigUint::from_bytes_be(&ARG_PUBKEY_EXP),
        BigUint::from_bytes_be(&ARG_PUBKEY_MOD),
    );
    let pk_ita = (
        *b"ITA",
        1,
        BigUint::from_bytes_be(&ITA_PUBKEY_EXP),
        BigUint::from_bytes_be(&ITA_PUBKEY_MOD),
    );
    let ml = vec![pk_arg, pk_ita];
    let pnum_hash: [u8; LEN_PNUM_HASH] = PNUM_HASH;
    let todays_date: [u8; LEN_DATE] = TODAYS_DATE;
    let instance = (ml, pnum_hash, todays_date);
    // Private inputs
    let dg1: [u8; LEN_DG1] = *DG1;
    let sod: Vec<u8> = EFSOD.to_vec();
    let witness = (sod, dg1);

    let relation = PassportRelation;
    let g = pgen::Generator::new(&relation);

    let proof = g.generate_proof(&relation, &instance, witness);
    println!("\nProof:\n{}\n", hex::encode(&proof));

    let verif = g.verify_proof(&instance, &proof);
    println!("\nResult: {}", pgen::to_string(verif));
}
