use crate::ctx::CTX;
use crate::storage;
use axum::{
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Json as ResponseJson, Response},
};
use circuits::passport::{LEN_DATE, LEN_NAT, LEN_PNUM_HASH, PassportRelation};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Deserialize)]
pub struct VerifyProofReq {
    pub master_list: Vec<(String, u8, PublicKey)>,
    pub pnum_hash: String,
    pub todays_date: String,
    pub proof: String,
}

#[derive(Deserialize)]
pub struct PublicKey {
    pub e: String,
    pub m: String,
}

#[derive(Serialize)]
pub struct VerifyProofRes {
    pub msg: String,
}

#[derive(Debug, Error)]
pub enum VerifyProofError {
    #[error("Context not initialized")]
    ContextNotInitialized,

    #[error("Invalid max_date length")]
    InvalidMaxDateLength,

    #[error("Invalid passport number hash length")]
    InvalidPnumHashLength,

    #[error("Invalid nationality length")]
    InvalidNationalityLength,

    #[error("Invalid hex in {field:?}: {source}")]
    InvalidHex {
        field: HexField,
        #[source]
        source: hex::FromHexError,
    },
}

#[derive(Debug)]
pub enum HexField {
    PubkeyMod,
    PubkeyExp,
    PnumHash,
    Proof,
}

impl IntoResponse for VerifyProofError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::ContextNotInitialized => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidMaxDateLength
            | Self::InvalidNationalityLength
            | Self::InvalidPnumHashLength
            | Self::InvalidHex { .. } => StatusCode::BAD_REQUEST,
        };

        tracing::info!(error = %self);

        status.into_response()
    }
}

pub async fn verify_proof(
    Json(payload): Json<VerifyProofReq>,
) -> Result<ResponseJson<VerifyProofRes>, VerifyProofError> {
    let ctx = CTX.get().ok_or(VerifyProofError::ContextNotInitialized)?;

    let ml: Vec<([u8; LEN_NAT], u8, BigUint, BigUint)> = payload
        .master_list
        .into_iter()
        .map(|item| {
            let c: &[u8; LEN_NAT] = item
                .0
                .as_bytes()
                .try_into()
                .expect("string must be exactly 3 bytes");

            let e = BigUint::from_bytes_be(&hex::decode(item.2.e).map_err(|e| {
                VerifyProofError::InvalidHex {
                    field: HexField::PubkeyExp,
                    source: e,
                }
            })?);

            let m = BigUint::from_bytes_be(&hex::decode(item.2.m).map_err(|e| {
                VerifyProofError::InvalidHex {
                    field: HexField::PubkeyMod,
                    source: e,
                }
            })?);

            Ok((*c, item.1, e, m))
        })
        .collect::<Result<Vec<_>, VerifyProofError>>()?;

    if payload.pnum_hash.len() != 2 * LEN_PNUM_HASH {
        return Err(VerifyProofError::InvalidPnumHashLength);
    }
    let mut pnum_hash = [0u8; LEN_PNUM_HASH];
    pnum_hash.copy_from_slice(&hex::decode(&payload.pnum_hash).map_err(|e| {
        VerifyProofError::InvalidHex {
            field: HexField::PnumHash,
            source: e,
        }
    })?);

    if payload.todays_date.len() != LEN_DATE {
        return Err(VerifyProofError::InvalidMaxDateLength);
    }
    let mut todays_date = [0u8; LEN_DATE];
    todays_date.copy_from_slice(payload.todays_date.as_bytes());

    let instance = (ml, pnum_hash, todays_date);
    let proof = hex::decode(&payload.proof).map_err(|e| VerifyProofError::InvalidHex {
        field: HexField::Proof,
        source: e,
    })?;

    let valid: bool = midnight_zk_stdlib::verify::<PassportRelation, blake2b_simd::State>(
        &ctx.srs.verifier_params(),
        &ctx.vk,
        &instance,
        None,
        proof.as_slice(),
    )
    .is_ok();

    tracing::info!("Received {} proof", to_string(valid));

    if !valid {
        return Ok(ResponseJson(VerifyProofRes {
            msg: "INVALID PROOF".into(),
        }));
    }

    if storage::get_entry(&payload.pnum_hash).is_some() {
        return Ok(ResponseJson(VerifyProofRes {
            msg: "WELCOME BACK!".into(),
        }));
    } else {
        storage::add_entry(&payload.pnum_hash, "");

        return Ok(ResponseJson(VerifyProofRes {
            msg: "WELCOME NEW USER!".into(),
        }));
    }
}

fn to_string(result: bool) -> &'static str {
    match result {
        true => "VALID",
        false => "INVALID",
    }
}
