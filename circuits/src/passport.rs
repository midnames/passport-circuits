use hex_literal::hex;
use midnight_circuits::{
    biguint::AssignedBigUint,
    instructions::{
        AssertionInstructions, AssignmentInstructions, ControlFlowInstructions, PublicInputInstructions,
        VectorInstructions,
    },
    types::{AssignedBit, AssignedByte, AssignedNative, AssignedVector, InnerValue, Instantiable},
};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};
use num_bigint::BigUint;
use rsa::{BigUint as RsaBigUint, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::ops::Sub;

type F = midnight_curves::Fq;

const NB_DATE: u32 = 32;

pub const LEN_NAT: usize = 3;
pub type PubKey = ([u8; LEN_NAT], u8, BigUint, BigUint);

// Instance: (ml, pnum_hash, todays_date)
pub const LEN_PUBKEY_EXP: u32 = 16;
pub const LEN_PUBKEY_MOD: u32 = 512;
type IMasterlist = Vec<PubKey>;
pub const LEN_PNUM_HASH: usize = 32;
type IPnumHash = [u8; LEN_PNUM_HASH];
pub const LEN_DATE: usize = 8;
type IDate = [u8; LEN_DATE];

// Witness: (sod, dg1)
pub const MAX_LEN_SOD: usize = 2048;
type WSod = Vec<u8>;
pub const LEN_DG1: usize = 93;
type WDg1 = [u8; LEN_DG1];

pub enum KeyType {
    Sha256WithRSAEncryption,
    Sha1WithRSAEncryption,
}

impl KeyType {
    pub fn value(&self) -> u8 {
        match self {
            KeyType::Sha256WithRSAEncryption => 0,
            KeyType::Sha1WithRSAEncryption => 1,
        }
    }
}

#[derive(Clone, Default)]
pub struct PassportRelation;

impl crate::Circuit for PassportRelation {
    const K: u32 = 15;
}

impl Relation for PassportRelation {
    type Instance = (IMasterlist, IPnumHash, IDate);
    type Witness = (WSod, WDg1);

    fn format_instance((ml, pnum_hash, date): &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(ml
            .iter()
            .flat_map(|key| {
                key.0
                    .iter()
                    .flat_map(AssignedByte::<F>::as_public_input)
                    .chain(AssignedByte::<F>::as_public_input(&key.1))
                    .chain(AssignedBigUint::<F>::as_public_input(&key.2, 8 * LEN_PUBKEY_EXP))
                    .chain(AssignedBigUint::<F>::as_public_input(&key.3, 8 * LEN_PUBKEY_MOD))
            })
            .chain(pnum_hash.iter().flat_map(AssignedByte::<F>::as_public_input))
            .chain(date.iter().flat_map(AssignedByte::<F>::as_public_input))
            .collect())
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let parser = std_lib.parser();
        let biguint = std_lib.biguint();

        // --- PUBLIC INPUTS ---

        let pnum_hash: [Value<u8>; LEN_PNUM_HASH] = instance.as_ref().map(|(_, x2, _)| *x2).transpose_array();
        let todays_date: [Value<u8>; LEN_DATE] = instance.as_ref().map(|(_, _, x3)| *x3).transpose_array();
        let ml: Vec<Value<PubKey>> = instance.map(|(x1, _, _)| x1).transpose_vec(2);

        let ml: Vec<([Value<u8>; 3], Value<u8>, Value<BigUint>, Value<BigUint>)> = unzip(ml);
        let ml: Vec<(
            Vec<AssignedByte<F>>,
            AssignedByte<F>,
            AssignedBigUint<F>,
            AssignedBigUint<F>,
        )> = ml
            .into_iter()
            .map(|(c, a, e, m)| {
                let c: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &c)?;
                let a: AssignedByte<F> = std_lib.assign(layouter, a)?;
                let e: AssignedBigUint<F> = biguint.assign_biguint(layouter, e, 8 * LEN_PUBKEY_EXP)?;
                let m: AssignedBigUint<F> = biguint.assign_biguint(layouter, m, 8 * LEN_PUBKEY_MOD)?;

                c.iter()
                    .try_for_each(|byte| std_lib.constrain_as_public_input(layouter, byte))?;
                std_lib.constrain_as_public_input(layouter, &a)?;
                biguint.constrain_as_public_input(layouter, &e, 8 * LEN_PUBKEY_EXP)?;
                biguint.constrain_as_public_input(layouter, &m, 8 * LEN_PUBKEY_MOD)?;

                Ok((c, a, e, m))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let pnum_hash: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &pnum_hash)?;
        pnum_hash
            .iter()
            .try_for_each(|byte| std_lib.constrain_as_public_input(layouter, byte))?;

        let todays_date: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &todays_date)?;
        todays_date
            .iter()
            .try_for_each(|byte| std_lib.constrain_as_public_input(layouter, byte))?;

        // --- PRIVATE INPUTS ---

        let dg1: [Value<u8>; LEN_DG1] = witness.as_ref().map(|(_, x2)| *x2).transpose_array();
        let sod: Value<Vec<u8>> = witness.map(|(x1, _)| x1);

        let dg1: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &dg1)?;
        let sod: AssignedVector<F, AssignedByte<F>, MAX_LEN_SOD, 64> =
            std_lib.assign_with_filler(layouter, sod, None)?;

        //  - STEPS -
        //
        // 1. Verify DSC is signed by CSCA (using CSCA public key): The DSC contains the TBS and the SIGNATURE.
        //    With the CSCA public key we verify the SIGNATURE over the TBS.
        // 2. Extract public key from verified DSC: The DSC's TBS contains the public key. This public key is used
        //    to verify the SA signature found in the EF.SOD.
        // 3. Verify SA signature over signed attributes (using the public key from DSC's TBS)
        // 4. Extract LDSSecurityObject from signed attributes (now trusted)
        // 5. Verify LDSSecurityObject hash from signed attributes
        // 6. Verify DG1 hash from LDSSecurityObject

        //
        // 1. Verify DSC is signed by CSCA (using CSCA public key)
        //   a. Parse TBS and SIGNATRE from EFSOD
        //   b. Verify over each signature in the masterlist
        //

        let val_false: AssignedBit<F> = std_lib.assign(layouter, Value::known(false))?;
        let val_true: AssignedBit<F> = std_lib.assign(layouter, Value::known(true))?;

        let tbs: Value<Vec<u8>> = sod.value().as_ref().map(|v: &Vec<u8>| extract_tbs(&v).to_vec());
        let tbs: AssignedVector<F, AssignedByte<F>, 2048, 64> = std_lib.assign_with_filler(layouter, tbs, None)?;

        let sig: Value<Vec<u8>> = sod.value().as_ref().map(|v: &Vec<u8>| extract_signature(&v).to_vec());
        let sig: AssignedVector<F, AssignedByte<F>, 2048, 64> = std_lib.assign_with_filler(layouter, sig, None)?;

        let bit = some_key_matches(std_lib, layouter, val_false, val_true, &tbs, &sig, ml)?;
        std_lib.assert_true(layouter, &bit)?;

        //
        // 2. Extract public key from verified DSC
        //

        let (modulus, exponent) = sod.value().as_ref().map(|v: &Vec<u8>| extract_pubkey(&v)).unzip();
        let modulus: AssignedVector<F, AssignedByte<F>, 2048, 64> =
            std_lib.assign_with_filler(layouter, modulus, None)?;
        let exponent: AssignedVector<F, AssignedByte<F>, 8, 8> =
            std_lib.assign_with_filler(layouter, exponent, None)?;

        //
        // 3. Verify SA signature over signed attributes
        //

        let signed_att: Value<Vec<u8>> = sod
            .value()
            .as_ref()
            .map(|v: &Vec<u8>| extract_signed_attributes(&v).to_vec());
        let signed_att: AssignedVector<F, AssignedByte<F>, 2048, 64> =
            std_lib.assign_with_filler(layouter, signed_att, None)?;

        let signature: Value<Vec<u8>> = sod
            .value()
            .as_ref()
            .map(|v: &Vec<u8>| extract_signer_signature(&v).to_vec());
        let signature: AssignedVector<F, AssignedByte<F>, 2048, 64> =
            std_lib.assign_with_filler(layouter, signature, None)?;

        let b2: Value<bool> = signed_att
            .value()
            .zip(signature.value())
            .zip(modulus.value().zip(exponent.value()))
            .map(|((sa, sig), (m, e))| {
                let pubkey = RsaPublicKey::new(RsaBigUint::from_bytes_be(&m), RsaBigUint::from_bytes_be(&e)).unwrap();
                verify_rsa_signature(&sa, &sig, &pubkey)
            });
        let b2: AssignedBit<F> = std_lib.assign(layouter, b2)?;
        std_lib.assert_true(layouter, &b2)?;

        //
        // --- NOW WE TRUST SIGNED ATTRIBUTES ---
        //

        let lds_obj = sod.value().as_ref().map_with_result(|seq: &Vec<u8>| {
            let prefix: [u8; 14] = hex!("0606678108010101a0818f04818c");

            let Some(idx): Option<usize> = seq.windows(prefix.len()).position(|window: &[u8]| window == prefix) else {
                return Err(Error::ConstraintSystemFailure);
            };
            let idx = idx + prefix.len();

            Ok(seq[idx..idx + 140].to_vec())
        })?;
        let lds_obj: AssignedVector<F, AssignedByte<F>, 256, 64> =
            std_lib.assign_with_filler(layouter, lds_obj, None)?;

        // --- VERIFY AUTHENTICITY OF DG1 ---
        //
        // 4. Extract LDS_HASH from SA_BYTES and compare
        // 5. Extract DG1_HASH from LDS_BYTES and compare

        // 4. Extract LDS_HASH from SA_BYTES and compare
        let prefix: [u8; 15] = hex!("06092a864886f70d01090431220420");
        let extracted_hash: [Value<u8>; 32] = signed_att
            .value()
            .zip(Value::known(prefix.as_slice()))
            .map_with_result(extract_hash_after_prefix)?
            .transpose_array();
        let extracted_hash: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &extracted_hash)?;

        let lds_hash = std_lib.sha256_varlen(layouter, &lds_obj)?;
        assert_str_equal(std_lib, layouter, &extracted_hash, &lds_hash)?;

        // 5. Extract DG1_HASH from LDS_BYTES and compare
        let prefix: [u8; 5] = hex!("0201010420");
        let extracted_hash: [Value<u8>; 32] = lds_obj
            .value()
            .zip(Value::known(prefix.as_slice()))
            .map_with_result(extract_hash_after_prefix)?
            .transpose_array();
        let extracted_hash: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &extracted_hash)?;
        let dg1_hash: [AssignedByte<F>; 32] = std_lib.sha2_256(layouter, &dg1)?;
        assert_str_equal(std_lib, layouter, &extracted_hash, &dg1_hash)?;

        // --- VALIDATE MRZ DATA ---

        // TODO: extract the MRZ in a more robust way
        // Skip the DG1 wrapper (ASN.1 encoding)
        let idx: AssignedNative<F> = std_lib.assign_fixed(layouter, F::from(5))?;
        let mrz: Vec<AssignedByte<F>> = parser.fetch_bytes(layouter, &dg1, &idx, 88)?;

        // Check passport number hash
        check_enrollment_handler(std_lib, layouter, &mrz, &pnum_hash)?;

        // Validate preamble
        let idx: AssignedNative<F> = std_lib.assign_fixed(layouter, F::from(0))?;
        let preamble: Vec<AssignedByte<F>> = parser.fetch_bytes(layouter, &mrz, &idx, 2)?;
        assert_str_equal_to_fixed(std_lib, layouter, &preamble, b"P<")?;

        // Extract todays_year
        let idx: AssignedNative<F> = std_lib.assign_fixed(layouter, F::from(0))?;
        let todays_year: Vec<AssignedByte<F>> = parser.fetch_bytes(layouter, &todays_date, &idx, 4)?;

        // Parse todays_date
        let todays_date: AssignedNative<F> = parser.ascii_to_int(layouter, &todays_date)?;

        // Parse exp_date
        let idx: AssignedNative<F> = std_lib.assign_fixed(layouter, F::from(65))?;
        let exp_date: Vec<AssignedByte<F>> = parser.fetch_bytes(layouter, &mrz, &idx, 6)?;
        let seq: Value<Vec<u8>> = Value::from_iter(exp_date.iter().map(|b| b.value()));
        let exp_date: Value<[u8; LEN_DATE]> = seq.map(|seq: Vec<u8>| {
            let mut v = [0u8; LEN_DATE];
            v[0] = b'2';
            v[1] = b'0';
            v[2..].copy_from_slice(&seq);
            v
        });
        let exp_date: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &exp_date.transpose_array())?;
        let exp_date: AssignedNative<F> = parser.ascii_to_int(layouter, &exp_date)?;

        // Assert: todays_date < exp_date
        let b: AssignedBit<F> = std_lib.lower_than(layouter, &todays_date, &exp_date, NB_DATE)?;
        std_lib.assert_true(layouter, &b)?;

        // Parse birthdate
        let idx: AssignedNative<F> = std_lib.assign_fixed(layouter, F::from(57))?;
        let birthdate: Vec<AssignedByte<F>> = parser.fetch_bytes(layouter, &mrz, &idx, 6)?;
        let seq_y: Value<Vec<u8>> = Value::from_iter(todays_year.iter().map(|b| b.value()));
        let seq_bd: Value<Vec<u8>> = Value::from_iter(birthdate.iter().map(|b| b.value()));
        let birthdate: Value<[u8; LEN_DATE]> =
            seq_y
                .zip(seq_bd)
                .map_with_result(|(todays_y, seq_bd): (Vec<u8>, Vec<u8>)| -> Result<[u8; 8], Error> {
                    let todays_year: u8 = std::str::from_utf8(&todays_y[2..4])
                        .map_err(|_| Error::ConstraintSystemFailure)?
                        .parse()
                        .map_err(|_| Error::ConstraintSystemFailure)?;
                    let birth_year: u8 = std::str::from_utf8(&seq_bd[0..2])
                        .map_err(|_| Error::ConstraintSystemFailure)?
                        .parse()
                        .map_err(|_| Error::ConstraintSystemFailure)?;

                    let y: &[u8; 2] = if birth_year > todays_year { b"19" } else { b"20" };

                    let mut v = [0u8; LEN_DATE];
                    v[0] = y[0];
                    v[1] = y[1];
                    v[2..].copy_from_slice(&seq_bd);

                    Ok(v)
                })?;
        let birthdate: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &birthdate.transpose_array())?;
        let birthdate: AssignedNative<F> = parser.ascii_to_int(layouter, &birthdate)?;

        // Compute: max_date = todays_date - 18 years
        let max_date: Value<F> = todays_date.value_field().map(|x| x.sub(F::from(18 * 10000))).evaluate();
        let max_date: AssignedNative<F> = std_lib.assign(layouter, max_date)?;

        // Assert: birthdate < max_date
        let b: AssignedBit<F> = std_lib.lower_than(layouter, &birthdate, &max_date, NB_DATE)?;
        std_lib.assert_true(layouter, &b)?;

        Ok(())
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            sha2_256: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(Self)
    }
}

fn assert_str_equal(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    str1: &[AssignedByte<F>],
    str2: &[AssignedByte<F>],
) -> Result<(), Error> {
    if str1.len() != str2.len() {
        return Err(Error::ConstraintSystemFailure);
    }
    for (b1, b2) in str1.iter().zip(str2.iter()) {
        std_lib.assert_equal(layouter, b1, b2)?
    }
    Ok(())
}

fn assert_str_equal_to_fixed(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    str: &[AssignedByte<F>],
    fixed: &[u8],
) -> Result<(), Error> {
    if fixed.len() != str.len() {
        return Err(Error::ConstraintSystemFailure);
    };
    for (f, b) in fixed.iter().zip(str.iter()) {
        std_lib.assert_equal_to_fixed(layouter, b, *f)?
    }
    Ok(())
}

fn extract_hash_after_prefix((seq, prefix): (Vec<u8>, &[u8])) -> Result<[u8; 32], Error> {
    let Some(idx): Option<usize> = seq.windows(prefix.len()).position(|window: &[u8]| window == prefix) else {
        return Err(Error::ConstraintSystemFailure);
    };
    let idx = idx + prefix.len();

    let mut v = [0u8; 32];
    v.copy_from_slice(&seq[idx..idx + 32]);

    Ok(v)
}

// fn extract_hash((sig, (m, e)): (BigUint, (BigUint, BigUint))) -> Result<[u8; 32], Error> {
//     // d = sig^e mod m
//     let d: BigUint = sig.modpow(&e, &m);
//
//     // raw bytes of decoded block
//     let d_bytes: Vec<u8> = d.to_bytes_be();
//
//     // pad to modulus size (256 bytes)
//     let mut out = [0u8; 256];
//     out[256 - d_bytes.len()..].copy_from_slice(&d_bytes);
//
//     // strip PKCS#1 v1.5 padding
//     // expect: 00 01 FF FF ... FF 00 <digestInfo>
//     let mut i = 0;
//     // leading 00
//     if out[i] != 0x00 {
//         return Err(Error::ConstraintSystemFailure);
//     }
//     i += 1;
//     // 01
//     if out[i] != 0x01 {
//         return Err(Error::ConstraintSystemFailure);
//     };
//     i += 1;
//     // FF bytes until 00
//     while out[i] == 0xFF {
//         i += 1;
//     }
//     // this must be 00
//     if out[i] != 0x00 {
//         return Err(Error::ConstraintSystemFailure);
//     }
//     i += 1;
//
//     // now out[i..] = ASN.1 digestInfo
//     let digest_info: &[u8] = &out[i..];
//
//     // ASN.1 header is ALWAYS 19 bytes for SHA-256:
//     let sha256_prefix: [u8; 19] = [
//         0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
//         0x20,
//     ];
//
//     // check prefix
//     for (a, b) in sha256_prefix.iter().zip(digest_info[0..19].iter()) {
//         if a != b {
//             return Err(Error::ConstraintSystemFailure);
//         }
//     }
//
//     // extract hash (last 32 bytes)
//     let recovered_hash: [u8; 32] = match digest_info[19..(19 + 32)].try_into() {
//         Ok(hash) => hash,
//         Err(_) => return Err(Error::ConstraintSystemFailure),
//     };
//
//     Ok(recovered_hash)
// }

fn extract_tbs(sod: &[u8]) -> &[u8] {
    // Look for the X.509 certificate structure
    // Certificate ::= SEQUENCE (30 82 xx xx for large certs)
    // Inside: TBSCertificate (30 82), AlgorithmIdentifier (30), signature (03)

    // Find certificate by looking for pattern:
    // 30 82 (large SEQUENCE) followed eventually by another 30 82 (TBS)
    let mut pos = 0;
    while pos < sod.len() - 4 {
        if sod[pos] == 0x30 && sod[pos + 1] == 0x82 {
            let cert_len = u16::from_be_bytes([sod[pos + 2], sod[pos + 3]]) as usize;

            // Check if this looks like a certificate (reasonable size)
            if cert_len > 500 && cert_len < 5000 {
                // Check if the next element (after the SEQUENCE header) is also a SEQUENCE
                let inner_pos = pos + 4;
                if inner_pos + 2 < sod.len() && sod[inner_pos] == 0x30 {
                    // This looks like a certificate with TBS inside
                    let tbs_start = inner_pos;

                    // Read TBS length
                    if sod[tbs_start + 1] == 0x82 {
                        let len = u16::from_be_bytes([sod[tbs_start + 2], sod[tbs_start + 3]]) as usize;
                        return &sod[tbs_start..tbs_start + 4 + len];
                    } else if sod[tbs_start + 1] == 0x81 {
                        let len = sod[tbs_start + 2] as usize;
                        return &sod[tbs_start..tbs_start + 3 + len];
                    } else if sod[tbs_start + 1] < 0x80 {
                        let len = sod[tbs_start + 1] as usize;
                        return &sod[tbs_start..tbs_start + 2 + len];
                    }
                }
            }
        }
        pos += 1;
    }

    panic!("TBS certificate not found");
}

fn verify_rsa_signature(msg: &[u8], signature: &[u8], pubkey: &RsaPublicKey) -> bool {
    let digest = Sha256::digest(msg);
    pubkey.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature).is_ok()
}

fn extract_signature(sod: &[u8]) -> &[u8] {
    // Find the certificate SEQUENCE first
    let mut cert_pos = 0;
    let mut cert_start = 0;
    let mut cert_len = 0;

    while cert_pos < sod.len() - 4 {
        if sod[cert_pos] == 0x30 && sod[cert_pos + 1] == 0x82 {
            let len = u16::from_be_bytes([sod[cert_pos + 2], sod[cert_pos + 3]]) as usize;

            if len > 500 && len < 5000 {
                let inner_pos = cert_pos + 4;
                if inner_pos + 2 < sod.len() && sod[inner_pos] == 0x30 {
                    cert_start = cert_pos;
                    cert_len = len;
                    break;
                }
            }
        }
        cert_pos += 1;
    }

    if cert_len == 0 {
        panic!("Certificate not found");
    }

    let cert_end = cert_start + 4 + cert_len;

    // Find the last BIT STRING (signature) in the certificate
    // It's typically 03 82 (BIT STRING with 2-byte length)
    let mut sig_pos = None;

    for i in cert_start..cert_end.saturating_sub(4) {
        if sod[i] == 0x03 && sod[i + 1] == 0x82 {
            sig_pos = Some(i);
        }
    }

    let sig_start = sig_pos.expect("Signature BIT STRING not found");
    let sig_len = u16::from_be_bytes([sod[sig_start + 2], sod[sig_start + 3]]) as usize;

    // Skip: tag (1) + 0x82 (1) + length (2) + unused bits (1) = 5 bytes
    let sig_data_start = sig_start + 5;
    let sig_data_end = sig_data_start + sig_len - 1; // -1 for the unused bits byte

    &sod[sig_data_start..sig_data_end]
}

// // To find the DG1's hash
// // - find 06 06 67 81 08 01 01 01 (LDSSecurityObject OID)
// // - search for the first occurrence of 02 01 01 04 20, after it its the DG1's hash (32 bytes).
// fn extract_dg1_hash(sod: &[u8]) -> &[u8] {
//     let lds_oid_pattern = [0x06, 0x06, 0x67, 0x81, 0x08, 0x01, 0x01, 0x01];
//     let oid_pos = sod
//         .windows(lds_oid_pattern.len())
//         .position(|window| window == lds_oid_pattern)
//         .expect("LDSSecurityObject OID not found");
//
//     let dg1_pattern = [0x02, 0x01, 0x01, 0x04, 0x20];
//     let search_start = oid_pos + lds_oid_pattern.len();
//
//     let dg1_pos = sod[search_start..]
//         .windows(dg1_pattern.len())
//         .position(|window| window == dg1_pattern)
//         .expect("DG1 hash pattern not found");
//
//     let hash_start = search_start + dg1_pos + dg1_pattern.len();
//     let hash_end = hash_start + 32;
//
//     &sod[hash_start..hash_end]
// }

fn extract_pubkey(sod: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // First find the TBS certificate
    let mut cert_pos = 0;
    let mut tbs_start = 0;
    let mut tbs_len = 0;

    while cert_pos < sod.len() - 4 {
        if sod[cert_pos] == 0x30 && sod[cert_pos + 1] == 0x82 {
            let cert_len = u16::from_be_bytes([sod[cert_pos + 2], sod[cert_pos + 3]]) as usize;

            if cert_len > 500 && cert_len < 5000 {
                let inner_pos = cert_pos + 4;
                if inner_pos + 2 < sod.len() && sod[inner_pos] == 0x30 {
                    tbs_start = inner_pos;
                    if sod[tbs_start + 1] == 0x82 {
                        tbs_len = u16::from_be_bytes([sod[tbs_start + 2], sod[tbs_start + 3]]) as usize;
                    }
                    break;
                }
            }
        }
        cert_pos += 1;
    }

    if tbs_len == 0 {
        panic!("TBS certificate not found");
    }

    let tbs_end = tbs_start + 4 + tbs_len;

    // Look for SubjectPublicKeyInfo in TBS
    // It's a SEQUENCE (30 82) containing:
    //   - AlgorithmIdentifier SEQUENCE
    //   - BIT STRING (03 82) with the actual key

    // Search for a BIT STRING (03 82) in the TBS that contains another SEQUENCE
    // This is the public key
    let mut pos = tbs_start;
    while pos < tbs_end - 4 {
        if sod[pos] == 0x03 && sod[pos + 1] == 0x82 {
            // Skip: tag (1) + 0x82 (1) + length (2) + unused bits (1) = 5 bytes
            let bitstring_start = pos + 5;

            // Check if it starts with SEQUENCE (30 82) - RSA public key structure
            if bitstring_start + 4 < sod.len() && sod[bitstring_start] == 0x30 && sod[bitstring_start + 1] == 0x82 {
                // Inside this SEQUENCE are two INTEGERs: modulus (n) and exponent (e)
                let seq_start = bitstring_start + 4; // Skip 30 82 xx xx

                // First INTEGER is the modulus
                if sod[seq_start] == 0x02 {
                    let (modulus, next_pos) = extract_integer(sod, seq_start);

                    // Second INTEGER is the exponent
                    if sod[next_pos] == 0x02 {
                        let (exponent, _) = extract_integer(sod, next_pos);
                        return (modulus, exponent);
                    }
                }
            }
        }
        pos += 1;
    }

    panic!("Public key not found");
}

// Helper function to extract an INTEGER from DER encoding
fn extract_integer(data: &[u8], pos: usize) -> (Vec<u8>, usize) {
    if data[pos] != 0x02 {
        panic!("Expected INTEGER tag");
    }

    let len_byte = data[pos + 1];

    if len_byte == 0x82 {
        // 2-byte length
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start + len;

        // Skip leading zero byte if present (used for positive integers with high bit set)
        let value = if data[start] == 0x00 {
            data[start + 1..end].to_vec()
        } else {
            data[start..end].to_vec()
        };

        (value, end)
    } else if len_byte == 0x81 {
        // 1-byte length
        let len = data[pos + 2] as usize;
        let start = pos + 3;
        let end = start + len;

        let value = if data[start] == 0x00 {
            data[start + 1..end].to_vec()
        } else {
            data[start..end].to_vec()
        };

        (value, end)
    } else {
        // Short form length
        let len = len_byte as usize;
        let start = pos + 2;
        let end = start + len;

        let value = if data[start] == 0x00 {
            data[start + 1..end].to_vec()
        } else {
            data[start..end].to_vec()
        };

        (value, end)
    }
}

fn extract_signed_attributes(sod: &[u8]) -> Vec<u8> {
    // In SignerInfo, signed attributes come after:
    // - version (INTEGER)
    // - sid (SignerIdentifier)
    // - digestAlgorithm (AlgorithmIdentifier)
    // - [0] IMPLICIT SignedAttributes (what we want)
    //
    // The signed attributes contain PKCS#9 OIDs starting with 2A 86 48 86 F7 0D 01 09
    // Pattern: A0 (tag) + length + 30 (SEQUENCE for first attribute) + length + 06 09 2A 86 48...

    let mut pos = 0;
    while pos < sod.len() - 20 {
        // Look for A0 followed by common pattern in signed attributes
        // A0, then after the length encoding, we expect to see 30 (SEQUENCE) for the first Attribute
        if sod[pos] == 0xA0 {
            let (len, header_len) = if sod[pos + 1] == 0x82 {
                (u16::from_be_bytes([sod[pos + 2], sod[pos + 3]]) as usize, 4)
            } else if sod[pos + 1] == 0x81 {
                (sod[pos + 2] as usize, 3)
            } else if sod[pos + 1] < 0x80 {
                (sod[pos + 1] as usize, 2)
            } else {
                pos += 1;
                continue;
            };

            let end = pos + header_len + len;
            if end > sod.len() {
                pos += 1;
                continue;
            }

            // Check if content starts with SEQUENCE tag (30) - first attribute
            // and contains the PKCS#9 OID pattern shortly after
            let content_start = pos + header_len;
            if content_start < sod.len() && sod[content_start] == 0x30 {
                // Look for PKCS#9 OID pattern (2A 86 48 86 F7 0D 01 09) within first 20 bytes
                let search_end = (content_start + 20).min(end);
                let pkcs9_pattern = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09];

                for i in content_start..search_end.saturating_sub(pkcs9_pattern.len()) {
                    if sod[i..i + pkcs9_pattern.len()] == pkcs9_pattern {
                        // Found it! Extract and convert A0 to 31
                        let mut result = sod[pos..end].to_vec();
                        result[0] = 0x31;
                        return result;
                    }
                }
            }
        }
        pos += 1;
    }

    panic!("Signed attributes not found");
}

fn extract_signer_signature(sod: &[u8]) -> Vec<u8> {
    // The signature in SignerInfo is an OCTET STRING (04)
    // It comes after the signed attributes
    // Look for: 04 82 (OCTET STRING with 2-byte length)

    // First, find where signed attributes end to search after them
    let mut search_start = 0;

    // Find the A0 (signed attributes) first
    for i in 0..sod.len() - 4 {
        if sod[i] == 0xA0 {
            let len = if sod[i + 1] == 0x82 {
                let l = u16::from_be_bytes([sod[i + 2], sod[i + 3]]) as usize;
                let header = 4;
                search_start = i + header + l;
                l
            } else if sod[i + 1] == 0x81 {
                let l = sod[i + 2] as usize;
                let header = 3;
                search_start = i + header + l;
                l
            } else if sod[i + 1] < 0x80 {
                let l = sod[i + 1] as usize;
                let header = 2;
                search_start = i + header + l;
                l
            } else {
                continue;
            };

            if len > 20 && len < 1000 {
                break;
            }
        }
    }

    // Now search for OCTET STRING (04 82) after the signed attributes
    for i in search_start..sod.len() - 4 {
        if sod[i] == 0x04 && sod[i + 1] == 0x82 {
            let len = u16::from_be_bytes([sod[i + 2], sod[i + 3]]) as usize;

            // Signature is typically 128-512 bytes for RSA
            if len > 100 && len < 1000 {
                let sig_start = i + 4; // Skip 04 82 xx xx
                let sig_end = sig_start + len;
                return sod[sig_start..sig_end].to_vec();
            }
        } else if sod[i] == 0x04 && sod[i + 1] == 0x81 {
            let len = sod[i + 2] as usize;

            if len > 100 && len < 1000 {
                let sig_start = i + 3;
                let sig_end = sig_start + len;
                return sod[sig_start..sig_end].to_vec();
            }
        }
    }

    panic!("Signer signature not found");
}

// TODO: Add salt
fn check_enrollment_handler(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    mrz: &[AssignedByte<F>],
    pnum_hash: &[AssignedByte<F>],
) -> Result<(), Error> {
    let idx: AssignedNative<F> = std_lib.assign_fixed(layouter, F::from(44))?;
    let pnum: Vec<AssignedByte<F>> = std_lib.parser().fetch_bytes(layouter, mrz, &idx, 9)?;
    let pnum_computed_hash: [AssignedByte<F>; 32] = std_lib.sha2_256(layouter, &pnum)?;

    assert_str_equal(std_lib, layouter, &pnum_computed_hash, pnum_hash)?;

    Ok(())
}

fn unzip(list: Vec<Value<PubKey>>) -> Vec<([Value<u8>; 3], Value<u8>, Value<BigUint>, Value<BigUint>)> {
    list.into_iter()
        .map(|item| {
            let (ca, em): (Value<([u8; 3], u8)>, Value<(BigUint, BigUint)>) =
                item.map(|caem| ((caem.0, caem.1), (caem.2, caem.3))).unzip();
            let (c, a): (Value<[u8; 3]>, Value<u8>) = ca.unzip();
            let (e, m): (Value<BigUint>, Value<BigUint>) = em.unzip();
            (c.transpose_array(), a, e, m)
        })
        .collect()
}

fn some_key_matches(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    val_false: AssignedBit<F>,
    val_true: AssignedBit<F>,
    tbs: &AssignedVector<F, AssignedByte<F>, 2048, 64>,
    sig: &AssignedVector<F, AssignedByte<F>, 2048, 64>,
    ml: Vec<(
        Vec<AssignedByte<F>>,
        AssignedByte<F>,
        AssignedBigUint<F>,
        AssignedBigUint<F>,
    )>,
) -> Result<AssignedBit<F>, Error> {
    let mut res: AssignedBit<F> = val_false;

    for pk in ml {
        let b1: Value<bool> =
            tbs.value()
                .zip(sig.value())
                .zip(pk.2.value().zip(pk.3.value()))
                .map(|((tbs, sig), (e, m))| {
                    let csca_pubkey = RsaPublicKey::new(
                        RsaBigUint::from_bytes_be(&m.to_bytes_be()),
                        RsaBigUint::from_bytes_be(&e.to_bytes_be()),
                    )
                    .unwrap();

                    verify_rsa_signature(&tbs, &sig, &csca_pubkey)
                });
        let b1: AssignedBit<F> = std_lib.assign(layouter, b1)?;
        res = std_lib.select(layouter, &b1, &res, &val_true)?;
    }

    Ok(res)
}
