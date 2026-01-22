use circuits::{
    Circuit,
    passport::{LEN_DATE, LEN_DG1, LEN_NAT, LEN_PNUM_HASH, PassportRelation, PubKey},
};
use jni::errors::Error as JniError;
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JString},
    sys::{jint, jsize, jstring},
};
use num_bigint::BigUint;
use rand::rngs::OsRng;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_midnames_passportreader_zk_ZkProofManager_generateProof<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    ml_c: jsize,
    ml_bytes: JByteArray<'local>,
    pnum_hash: JByteArray<'local>,
    todays_date: JString<'local>,
    efsod: JByteArray<'local>,
    dg1: JByteArray<'local>,
) -> jstring {
    match generate_proof(&mut env, ml_c, ml_bytes, pnum_hash, todays_date, efsod, dg1) {
        Ok(result) => result,
        Err(e) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("Failed to generate proof: {}", e),
            );
            std::ptr::null_mut() // Return null on error
        }
    }
}

fn read_jbytearray_as_vec(env: &JNIEnv, byte_array: &JByteArray) -> Result<Vec<u8>, JniError> {
    env.convert_byte_array(byte_array)
}

#[allow(dead_code)]
fn read_jbytearray_as_biguint(env: &JNIEnv, byte_array: JByteArray) -> Result<BigUint, JniError> {
    let bytes: Vec<u8> = env.convert_byte_array(byte_array)?;
    let biguint = BigUint::from_bytes_be(&bytes);
    Ok(biguint)
}

fn read_jbytearray_as_array<const LENGTH: usize>(
    env: &JNIEnv,
    byte_array: &JByteArray,
) -> Result<[u8; LENGTH], Box<dyn std::error::Error>> {
    let length = env.get_array_length(byte_array)? as usize;

    if length != LENGTH {
        return Err(format!("Expected string of length {}, got {}", LENGTH, length).into());
    }

    let mut array = [0u8; LENGTH];
    env.get_byte_array_region(byte_array, 0, unsafe {
        std::slice::from_raw_parts_mut(array.as_mut_ptr() as *mut i8, LENGTH)
    })?;

    Ok(array)
}

fn read_jstring_as_array<const LENGTH: usize>(
    env: &mut JNIEnv,
    jstring: JString,
) -> Result<[u8; LENGTH], Box<dyn std::error::Error>> {
    let string: String = env.get_string(&jstring)?.into();

    if string.len() != LENGTH {
        return Err(format!("Expected string of length {}, got {}", LENGTH, string.len()).into());
    }

    let mut array = [0u8; LENGTH];
    array.copy_from_slice(string.as_bytes());

    Ok(array)
}

fn read_ml(
    env: &JNIEnv,
    ml_c: jint,
    ml_v: JByteArray,
) -> Result<Vec<PubKey>, Box<dyn std::error::Error>> {
    if ml_c < 0 {
        return Err("Invalid count: must be non-negative".into());
    }
    let ml_c: usize = ml_c as usize;
    let ml_v: Vec<u8> = env.convert_byte_array(ml_v)?;

    _read_ml(ml_c, ml_v)
}

fn _read_ml(ml_c: usize, ml_v: Vec<u8>) -> Result<Vec<PubKey>, Box<dyn std::error::Error>> {
    let mut res = Vec::<PubKey>::with_capacity(ml_c);
    let mut i: usize = 0;

    while i < ml_v.len() {
        if ml_v.len() - i < 4 {
            return Err("Not enough bytes (country and algorithm)".into());
        }
        let country: [u8; LEN_NAT] = ml_v[i..i + LEN_NAT]
            .try_into()
            .map_err(|_| "Failed to parse country")?;
        let algo: u8 = ml_v[i + LEN_NAT];
        i += LEN_NAT + 1;

        if ml_v.len() - i < 2 {
            return Err("Not enough bytes (len_e)".into());
        }
        let len_e: usize = u16::from_be_bytes([ml_v[i], ml_v[i + 1]]) as usize;
        if len_e == 0 {
            return Err("len_e cannot be zero".into());
        }
        i += 2;
        if ml_v.len() - i < len_e {
            return Err("Not enough bytes (e)".into());
        }
        let e: BigUint = BigUint::from_bytes_be(&ml_v[i..i + len_e]);
        i += len_e;

        if ml_v.len() - i < 2 {
            return Err("Not enough bytes (len_m)".into());
        }
        let len_m: usize = u16::from_be_bytes([ml_v[i], ml_v[i + 1]]) as usize;
        if len_m == 0 {
            return Err("len_m cannot be zero".into());
        }
        i += 2;
        if ml_v.len() - i < len_m {
            return Err("Not enough bytes (m)".into());
        }
        let m: BigUint = BigUint::from_bytes_be(&ml_v[i..i + len_m]);
        i += len_m;

        let pubkey = (country, algo, e, m);

        res.push(pubkey);
    }

    if i != ml_v.len() {
        return Err(format!("Unexpected trailing bytes: {} remaining", ml_v.len() - i).into());
    }

    if res.len() != ml_c as usize {
        return Err(format!("Expected {} entries, found {}", ml_c, res.len()).into());
    }

    Ok(res)
}

fn generate_proof<'local>(
    env: &mut JNIEnv<'local>,
    ml_c: jsize,
    ml_bytes: JByteArray<'local>,
    pnum_hash: JByteArray<'local>,
    todays_date: JString<'local>,
    efsod: JByteArray<'local>,
    dg1: JByteArray<'local>,
) -> Result<jstring, Box<dyn std::error::Error>> {
    let relation = PassportRelation;

    let srs = circuits::filecoin::load_srs(PassportRelation::K);

    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    // PUBLIC INPUTS

    let ml: Vec<PubKey> = read_ml(env, ml_c, ml_bytes)?;

    let pnum_hash: [u8; LEN_PNUM_HASH] =
        read_jbytearray_as_array::<LEN_PNUM_HASH>(env, &pnum_hash)?;
    let todays_date: [u8; LEN_DATE] = read_jstring_as_array::<LEN_DATE>(env, todays_date)?;

    let instance = (ml, pnum_hash, todays_date);

    // PRIVATE INPUTS

    let efsod: Vec<u8> = read_jbytearray_as_vec(env, &efsod)?;
    let dg1: [u8; LEN_DG1] = read_jbytearray_as_array::<LEN_DG1>(env, &dg1)?;

    let witness = (efsod, dg1);

    let proof: Vec<u8> = midnight_zk_stdlib::prove::<PassportRelation, blake2b_simd::State>(
        &srs, &pk, &relation, &instance, witness, OsRng,
    )?;

    let proof_hex: String = hex::encode(&proof);

    Ok(env.new_string(proof_hex)?.into_raw())
}

#[cfg(test)]
mod tests {
    use super::_read_ml;
    use hex_literal::hex;
    use num_bigint::BigUint;

    pub const ARG_PUBKEY_EXP: [u8; 3] = hex!("010001");
    pub const ARG_PUBKEY_MOD: [u8; 384] = hex!(
        "c9a6105edffbf21e91ce42dc29b024ca8fb2c0c28ba8fcc0710d8275943a058494cb785caa1735f72d23364e1c5580501fbaea283458c47363fcdf475b9f86db803c812d87921142c38eb199b4787a0957368e8d454794c16ca182431e373ab853e5f21d7766b86614e300d4853329aa1bf88082d10f5c095bcf2fc60b371f2a8f37e1bbc84cefd98926b7f499914dd5af7977b9a1113afeb89bf46d1162bf5bf7aa9a47c5a9b22979c1fafd9de434395cef7e46ea13603da949582713e9347df8e151079c108860854486ab31a51186eed42caaf63be699452e113cd5865917f71c0fd352faf2f6cf69b28a395102ad0e471828e08276413efd47017d1bc512b4b557b4fb0386881542c8ef4f75cfd4ac787ff345c886027d54ca0d23894ffcf9cc218ce7e0026e1b304c038b1ab12052e9ef217d3a020ec85141e0948a97d7b87b901edb46a8f6d27b7c52c2eaa27bb5ca32df9affd73bba4134c2d9c64d41e1cef44b5d35f69db5e31df0c871386adff87b934b5923adf5ebcb469140c49d"
    );
    pub const ITA_PUBKEY_EXP: [u8; 3] = hex!("010001");
    pub const ITA_PUBKEY_MOD: [u8; 384] = hex!(
        "caa6105edffbf21e91ce42dc29b024ca8fb2c0c28ba8fcc0710d8275943a058494cb785caa1735f72d23364e1c5580501fbaea283458c47363fcdf475b9f86db803c812d87921142c38eb199b4787a0957368e8d454794c16ca182431e373ab853e5f21d7766b86614e300d4853329aa1bf88082d10f5c095bcf2fc60b371f2a8f37e1bbc84cefd98926b7f499914dd5af7977b9a1113afeb89bf46d1162bf5bf7aa9a47c5a9b22979c1fafd9de434395cef7e46ea13603da949582713e9347df8e151079c108860854486ab31a51186eed42caaf63be699452e113cd5865917f71c0fd352faf2f6cf69b28a395102ad0e471828e08276413efd47017d1bc512b4b557b4fb0386881542c8ef4f75cfd4ac787ff345c886027d54ca0d23894ffcf9cc218ce7e0026e1b304c038b1ab12052e9ef217d3a020ec85141e0948a97d7b87b901edb46a8f6d27b7c52c2eaa27bb5ca32df9affd73bba4134c2d9c64d41e1cef44b5d35f69db5e31df0c871386adff87b934b5923adf5ebcb469140c49d"
    );

    fn populate_ml_v() -> Vec<u8> {
        let mut ml_v: Vec<u8> = Vec::with_capacity(2);

        // First entry: ITA
        ml_v.extend_from_slice(b"ITA"); // country
        ml_v.push(1); // algorithm
        ml_v.extend_from_slice(&(ITA_PUBKEY_EXP.len() as u16).to_be_bytes()); // len_e
        ml_v.extend_from_slice(&ITA_PUBKEY_EXP); // e
        ml_v.extend_from_slice(&(ITA_PUBKEY_MOD.len() as u16).to_be_bytes()); // len_m
        ml_v.extend_from_slice(&ITA_PUBKEY_MOD); // m

        // Second entry: ARG
        ml_v.extend_from_slice(b"ARG"); // country
        ml_v.push(0); // algorithm
        ml_v.extend_from_slice(&(ARG_PUBKEY_EXP.len() as u16).to_be_bytes()); // len_e
        ml_v.extend_from_slice(&ARG_PUBKEY_EXP); // e
        ml_v.extend_from_slice(&(ARG_PUBKEY_MOD.len() as u16).to_be_bytes()); // len_m
        ml_v.extend_from_slice(&ARG_PUBKEY_MOD); // m

        ml_v
    }

    #[test]
    fn test_read_ml() {
        let ml_c: usize = 2;
        let ml_v: Vec<u8> = populate_ml_v();

        // Expected result
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
        let expected = vec![pk_ita, pk_arg];

        // Parse and verify
        let result = _read_ml(ml_c, ml_v).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], expected[0]);
        assert_eq!(result[1], expected[1]);
    }

    #[test]
    fn test_read_ml_wrong_count() {
        let ml_c: usize = 1; // Expect 1 but provide 2
        let ml_v: Vec<u8> = populate_ml_v();

        let result = _read_ml(ml_c, ml_v);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Expected 1 entries, found 2")
        );
    }

    #[test]
    fn test_read_ml_zero_len_e() {
        let ml_c: usize = 1;
        let mut ml_v: Vec<u8> = Vec::new();

        ml_v.extend_from_slice(b"ARG");
        ml_v.push(0);
        ml_v.extend_from_slice(&0u16.to_be_bytes()); // len_e = 0

        let result = _read_ml(ml_c, ml_v);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("len_e cannot be zero")
        );
    }

    #[test]
    fn test_read_ml_truncated_data() {
        let ml_c: usize = 1;
        let mut ml_v: Vec<u8> = Vec::new();

        ml_v.extend_from_slice(b"ARG");
        ml_v.push(0);
        ml_v.extend_from_slice(&(ITA_PUBKEY_EXP.len() as u16).to_be_bytes());
        ml_v.extend_from_slice(&ITA_PUBKEY_EXP[..2]); // Truncated!

        let result = _read_ml(ml_c, ml_v);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Not enough bytes"));
    }
}
