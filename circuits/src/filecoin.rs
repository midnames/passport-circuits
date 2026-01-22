use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use std::io::Cursor;

const SRS_BYTES: &[u8] = include_bytes!("assets/bls_filecoin_2p17");

pub fn load_srs(k: u32) -> ParamsKZG<Bls12> {
    assert!(k <= 19, "We don't have an SRS for circuits of size {k}");

    let mut srs: ParamsKZG<Bls12> = ParamsKZG::read_custom(&mut Cursor::new(SRS_BYTES), SerdeFormat::RawBytesUnchecked)
        .expect("Failed to read embedded SRS");

    srs.downsize(k);

    srs
}
