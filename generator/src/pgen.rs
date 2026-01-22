use circuits::Circuit;
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zk_stdlib::{self, MidnightPK, MidnightVK, Relation};
use rand::rngs::OsRng;
use std::time::Instant;

fn start(msg: &str) -> Instant {
    println!("{msg}");
    Instant::now()
}

pub fn to_string(result: bool) -> &'static str {
    match result {
        true => "VALID",
        false => "INVALID",
    }
}

pub struct Generator<R: Circuit> {
    srs: ParamsKZG<Bls12>,
    vk: MidnightVK,
    pk: MidnightPK<R>,
}

impl<R: Circuit + Relation> Generator<R> {
    pub fn new(relation: &R) -> Generator<R> {
        let i_srs = start("Loading the SRS...");
        let srs = circuits::filecoin::load_srs(R::K);
        println!("Done! ({:?})", i_srs.elapsed());

        let i_setup_vk = start("Setting up the vk...");
        let vk = midnight_zk_stdlib::setup_vk(&srs, relation);
        println!("Done! ({:?})", i_setup_vk.elapsed());
        let i_setup_pk = start("Setting up the pk...");
        let pk = midnight_zk_stdlib::setup_pk(relation, &vk);
        println!("Done! ({:?})", i_setup_pk.elapsed());

        Generator { srs, vk, pk }
    }

    pub fn generate_proof(
        self: &Self,
        relation: &R,
        instance: &R::Instance,
        witness: R::Witness,
    ) -> Vec<u8> {
        let i_proof = start("Generating proof...");
        let proof = midnight_zk_stdlib::prove::<R, blake2b_simd::State>(
            &self.srs, &self.pk, relation, instance, witness, OsRng,
        )
        .expect("Proof generation should not fail");
        println!("Done! ({:?})", i_proof.elapsed());

        proof
    }

    pub fn verify_proof(self: &Self, instance: &R::Instance, proof: &[u8]) -> bool {
        let i_verif = start("Verifying proof...");
        let verif = midnight_zk_stdlib::verify::<R, blake2b_simd::State>(
            &self.srs.verifier_params(),
            &self.vk,
            instance,
            None,
            proof,
        );
        println!("Done! ({:?})", i_verif.elapsed());

        println!("\n{:?}", verif);

        verif.is_ok()
    }
}
