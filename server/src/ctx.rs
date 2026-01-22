use circuits::passport::PassportRelation;
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zk_stdlib::MidnightVK;
use std::sync::OnceLock;

pub static CTX: OnceLock<Ctx> = OnceLock::new();

pub struct Ctx {
    pub relation: PassportRelation,
    pub srs: ParamsKZG<Bls12>,
    pub vk: MidnightVK,
}
