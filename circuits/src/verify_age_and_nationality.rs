use midnight_circuits::{
    instructions::{AssertionInstructions, AssignmentInstructions, PublicInputInstructions},
    parsing::{DateFormat, Separator},
    types::{AssignedBit, AssignedByte, AssignedNative, InnerValue, Instantiable},
};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};

type F = midnight_curves::Fq;

// TODO: Optimize?
const N_BITS: u32 = 32;

// Instance
pub const DATE_LEN: usize = 10;
type DateArray = [u8; DATE_LEN];
pub const NAT_LEN: usize = 3;
type NatArray = [u8; NAT_LEN];

// Witness
pub const PAYLOAD_LEN: usize = 2048;
type Payload = [u8; PAYLOAD_LEN];

#[derive(Clone, Default)]
pub struct JsonVerifyAgeAndNationality;

impl crate::Circuit for JsonVerifyAgeAndNationality {
    const K: u32 = 13;
}

impl Relation for JsonVerifyAgeAndNationality {
    type Instance = (DateArray, NatArray); // (max_date, exp_nat)
    type Witness = Payload; // json

    fn format_instance((max_date, nationality): &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(max_date
            .iter()
            .chain(nationality.iter())
            .flat_map(AssignedByte::<F>::as_public_input)
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

        // Assign max_date as public input
        let max_date: Vec<AssignedByte<F>> =
            std_lib.assign_many(layouter, &instance.map(|(x, _)| x).transpose_array())?;
        max_date
            .iter()
            .try_for_each(|byte| std_lib.constrain_as_public_input(layouter, byte))?;

        // Assign exp_nat as public input
        let exp_nat: Vec<AssignedByte<F>> =
            std_lib.assign_many(layouter, &instance.map(|(_, y)| y).transpose_array())?;
        exp_nat
            .iter()
            .try_for_each(|byte| std_lib.constrain_as_public_input(layouter, byte))?;

        // Assign payload
        let payload: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &witness.transpose_array())?;

        // Parse birthdate
        let birthdate: Vec<AssignedByte<F>> = get_property(std_lib, layouter, &payload, b"dateOfBirth", DATE_LEN + 2)?;

        // Parse nationality
        let nationality: Vec<AssignedByte<F>> = get_property(std_lib, layouter, &payload, b"nationality", NAT_LEN + 2)?;

        // Assert: birthdate < max_date
        let format = (DateFormat::YYYYMMDD, Separator::Sep('-'));
        let max_date: AssignedNative<F> = parser.date_to_int(layouter, &max_date, format)?;
        let birthdate: AssignedNative<F> = parser.date_to_int(layouter, &birthdate[1..DATE_LEN + 1], format)?;
        let b: AssignedBit<F> = std_lib.lower_than(layouter, &birthdate, &max_date, N_BITS)?;
        std_lib.assert_true(layouter, &b)?;

        // Assert: nationality == exp_nat
        assert_str_match(std_lib, layouter, &exp_nat, &nationality[1..NAT_LEN + 1])?;

        Ok(())
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: false,
            poseidon: false,
            sha256: false,
            sha512: false,
            secp256k1: false,
            bls12_381: false,
            base64: false,
            nr_pow2range_cols: 1,
            automaton: false,
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(Self)
    }
}

fn get_property(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    body: &[AssignedByte<F>],
    property: &[u8],
    val_len: usize,
) -> Result<Vec<AssignedByte<F>>, Error> {
    let parser = std_lib.parser();

    let property = [b"\"", property, b"\":"].concat();
    let p_len = property.len();
    let seq: Value<Vec<u8>> = Value::from_iter(body.iter().map(|b| b.value()));

    let idx: Value<F> = seq.map(|seq: Vec<u8>| {
        let idx: usize = seq
            .windows(p_len)
            .position(|window: &[u8]| window == property)
            .expect("property should appear in the credential.");
        F::from(idx as u64)
    });

    let idx = std_lib.assign(layouter, idx)?; // idx will be range-checked in `fetch_bytes`.

    let raw_propety = parser.fetch_bytes(layouter, body, &idx, p_len + val_len)?;
    Ok(raw_propety[p_len..].to_vec())
}

fn assert_str_match(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    str1: &[AssignedByte<F>],
    str2: &[AssignedByte<F>],
) -> Result<(), Error> {
    assert_eq!(str1.len(), str2.len(), "Compared string lengths must match.");
    for (b1, b2) in str1.iter().zip(str2.iter()) {
        std_lib.assert_equal(layouter, b1, b2)?
    }
    Ok(())
}
