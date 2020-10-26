#![allow(non_snake_case)]
/*
    Multisig Schnorr
    Copyright 2018 by Kzen Networks
    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)
    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.
    @license GPL-3.0+ <https://github.com/KZen-networks/multisig-schnorr/blob/master/LICENSE>
*/

//! aggregated Schnorr {n,n}-Signatures
//!
//! See https://eprint.iacr.org/2018/068.pdf, https://eprint.iacr.org/2018/483.pdf subsection 5.1
use curv::{BigInt, FE, GE};

use curv::cryptographic_primitives::proofs::*;
use curv::elliptic::curves::traits::*;

use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::*;

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::*;

#[derive(Debug)]
pub struct KeyPair {
    pub public_key: GE,
    private_key: FE,
}

impl KeyPair {
    pub fn create() -> KeyPair {
        let ec_point: GE = ECPoint::generator();
        let private_key: FE = ECScalar::new_random();
        let public_key = ec_point.scalar_mul(&private_key.get_element());
        KeyPair {
            public_key,
            private_key,
        }
    }

    pub fn create_from_private_key(private_key: &BigInt) -> KeyPair {
        let ec_point: GE = ECPoint::generator();
        let private_key: FE = ECScalar::from(private_key);
        let public_key = ec_point.scalar_mul(&private_key.get_element());
        KeyPair {
            public_key,
            private_key,
        }
    }
}

#[derive(Debug)]
pub struct KeyAgg {
    pub apk: GE,
    pub hash: BigInt,
}

impl KeyAgg {
    pub fn key_aggregation(my_pk: &GE, other_pk: &GE) -> KeyAgg {
        let hash = HSha256::create_hash(&[
            &BigInt::from(1),
            &my_pk.bytes_compressed_to_big_int(),
            &my_pk.bytes_compressed_to_big_int(),
            &other_pk.bytes_compressed_to_big_int(),
        ]);
        let hash_fe: FE = ECScalar::from(&hash);
        let a1 = my_pk.scalar_mul(&hash_fe.get_element());

        let hash2 = HSha256::create_hash(&[
            &BigInt::from(1),
            &other_pk.bytes_compressed_to_big_int(),
            &my_pk.bytes_compressed_to_big_int(),
            &other_pk.bytes_compressed_to_big_int(),
        ]);
        let hash2_fe: FE = ECScalar::from(&hash2);
        let a2 = other_pk.scalar_mul(&hash2_fe.get_element());
        let apk = a2.add_point(&(a1.get_element()));
        KeyAgg { apk, hash }
    }

    pub fn key_aggregation_n(pks: &[GE], party_index: usize) -> KeyAgg {
        let bn_1 = BigInt::from(1);
        let x_coor_vec: Vec<BigInt> = pks
            .iter()
            .map(|pk| pk.bytes_compressed_to_big_int())
            .collect();

        let hash_vec: Vec<BigInt> = x_coor_vec
            .iter()
            .map(|pk| {
                let mut vec = Vec::new();
                vec.push(&bn_1);
                vec.push(pk);
                for mpz in x_coor_vec.iter().take(pks.len()) {
                    vec.push(mpz);
                }
                HSha256::create_hash(&vec)
            })
            .collect();

        let mut apk_vec: Vec<GE> = pks
            .iter()
            .zip(&hash_vec)
            .map(|(pk, hash)| {
                let hash_t: FE = ECScalar::from(&hash);
                let pki: GE = pk.clone();
                pki.scalar_mul(&hash_t.get_element())
            })
            .collect();

        let pk1 = apk_vec.remove(0);
        let sum = apk_vec
            .iter()
            .fold(pk1, |acc, pk| acc.add_point(&pk.get_element()));

        KeyAgg {
            apk: sum,
            hash: hash_vec[party_index].clone(),
        }
    }
}

#[derive(Debug)]
pub struct EphemeralKey {
    pub keypair: KeyPair,
    pub commitment: BigInt,
    pub blind_factor: BigInt,
}

impl EphemeralKey {
    pub fn create() -> EphemeralKey {
        let keypair = KeyPair::create();
        let (commitment, blind_factor) =
            HashCommitment::create_commitment(&keypair.public_key.bytes_compressed_to_big_int());
        EphemeralKey {
            keypair,
            commitment,
            blind_factor,
        }
    }

    pub fn create_from_private_key(x1: &KeyPair, message: &[u8]) -> EphemeralKey {
        let base_point: GE = ECPoint::generator();
        let hash_private_key_message =
            HSha256::create_hash(&[&x1.private_key.to_big_int(), &BigInt::from(message)]);
        let ephemeral_private_key: FE = ECScalar::from(&hash_private_key_message);
        let ephemeral_public_key = base_point.scalar_mul(&ephemeral_private_key.get_element());
        let (commitment, blind_factor) =
            HashCommitment::create_commitment(&ephemeral_public_key.bytes_compressed_to_big_int());
        EphemeralKey {
            keypair: KeyPair {
                public_key: ephemeral_public_key,
                private_key: ephemeral_private_key,
            },
            commitment,
            blind_factor,
        }
    }

    pub fn test_com(r_to_test: &GE, blind_factor: &BigInt, comm: &BigInt) -> bool {
        let computed_comm = &HashCommitment::create_commitment_with_user_defined_randomness(
            &r_to_test.bytes_compressed_to_big_int(),
            blind_factor,
        );
        computed_comm == comm
    }

    pub fn add_ephemeral_pub_keys(r1: &GE, r2: &GE) -> GE {
        r1.add_point(&r2.get_element())
    }

    pub fn hash_0(r_hat: &GE, apk: &GE, message: &[u8], musig_bit: bool) -> BigInt {
        if musig_bit {
            HSha256::create_hash(&[
                &BigInt::from(0),
                &r_hat.x_coor().unwrap(),
                &apk.bytes_compressed_to_big_int(),
                &BigInt::from(message),
            ])
        } else {
            HSha256::create_hash(&[
                &r_hat.x_coor().unwrap(),
                &apk.bytes_compressed_to_big_int(),
                &BigInt::from(message),
            ])
        }
    }

    pub fn sign(r: &EphemeralKey, c: &BigInt, x: &KeyPair, a: &BigInt) -> BigInt {
        let c_fe: FE = ECScalar::from(c);
        let a_fe: FE = ECScalar::from(a);
        let s_fe = r.keypair.private_key.clone() + (c_fe * x.private_key.clone() * a_fe);
        s_fe.to_big_int()
    }

    pub fn add_signature_parts(s1: BigInt, s2: &BigInt, r_tag: &GE) -> (BigInt, BigInt) {
        if *s2 == BigInt::from(0) {
            (r_tag.x_coor().unwrap(), s1)
        } else {
            let s1_fe: FE = ECScalar::from(&s1);
            let s2_fe: FE = ECScalar::from(&s2);
            let s1_plus_s2 = s1_fe.add(&s2_fe.get_element());
            (r_tag.x_coor().unwrap(), s1_plus_s2.to_big_int())
        }
    }
}

pub fn verify(
    signature: &BigInt,
    r_x: &BigInt,
    apk: &GE,
    message: &[u8],
    musig_bit: bool,
) -> Result<(), ProofError> {
    let base_point: GE = ECPoint::generator();

    let c = if musig_bit {
        HSha256::create_hash(&[
            &BigInt::from(0),
            &r_x,
            &apk.bytes_compressed_to_big_int(),
            &BigInt::from(message),
        ])
    } else {
        HSha256::create_hash(&[
            r_x,
            &apk.bytes_compressed_to_big_int(),
            &BigInt::from(message),
        ])
    };

    let signature_fe: FE = ECScalar::from(signature);
    let sG = base_point.scalar_mul(&signature_fe.get_element());
    let c: FE = ECScalar::from(&c);
    let cY = apk.scalar_mul(&c.get_element());
    let sG = sG.sub_point(&cY.get_element());
    if sG.x_coor().unwrap().to_hex() == r_x.to_hex() {
        Ok(())
    } else {
        Err(ProofError)
    }
}

pub fn verify_partial(
    signature: &FE,
    r_x: &BigInt,
    c: &FE,
    a: &FE,
    key_pub: &GE,
) -> Result<(), ProofError> {
    let g: GE = ECPoint::generator();
    let sG = g * signature;
    let cY = key_pub * a * c;
    let sG = sG.sub_point(&cY.get_element());
    if sG.x_coor().unwrap().to_hex() == *r_x.to_hex() {
        Ok(())
    } else {
        Err(ProofError)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use curv::BigInt;
    use curv::GE;
    extern crate hex;
    use curv::elliptic::curves::traits::*;

    #[test]
    fn test_multiparty_signing_for_two_parties() {
        let is_musig = true;
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = KeyPair::create();
        let party2_key = KeyPair::create();

        // round 1: send commitments to ephemeral public keys
        let party1_ephemeral_key = EphemeralKey::create();
        let party2_ephemeral_key = EphemeralKey::create();
        let party1_commitment = &party1_ephemeral_key.commitment;
        let party2_commitment = &party2_ephemeral_key.commitment;

        // round 2: send ephemeral public keys and check commitments
        // p1 release R1' and p2 test com(R1') = com(R1):
        assert!(EphemeralKey::test_com(
            &party2_ephemeral_key.keypair.public_key,
            &party2_ephemeral_key.blind_factor,
            party2_commitment
        ));
        // p2 release R2' and p1 test com(R2') = com(R2):
        assert!(EphemeralKey::test_com(
            &party1_ephemeral_key.keypair.public_key,
            &party1_ephemeral_key.blind_factor,
            party1_commitment
        ));

        // compute apk:
        let mut pks: Vec<GE> = Vec::new();
        pks.push(party1_key.public_key.clone());
        pks.push(party2_key.public_key.clone());
        let party1_key_agg = KeyAgg::key_aggregation_n(&pks, 0);
        let party2_key_agg = KeyAgg::key_aggregation_n(&pks, 1);
        assert_eq!(party1_key_agg.apk, party2_key_agg.apk);

        // compute R' = R1+R2:
        let party1_r_tag = EphemeralKey::add_ephemeral_pub_keys(
            &party1_ephemeral_key.keypair.public_key,
            &party2_ephemeral_key.keypair.public_key,
        );

        let party2_r_tag = EphemeralKey::add_ephemeral_pub_keys(
            &party1_ephemeral_key.keypair.public_key,
            &party2_ephemeral_key.keypair.public_key,
        );

        assert_eq!(party1_r_tag, party2_r_tag);

        // compute c = H0(Rtag || apk || message)
        let party1_h_0 =
            EphemeralKey::hash_0(&party1_r_tag, &party1_key_agg.apk, &message, is_musig);
        let party2_h_0 =
            EphemeralKey::hash_0(&party2_r_tag, &party2_key_agg.apk, &message, is_musig);
        assert_eq!(party1_h_0, party2_h_0);

        // compute partial signature s_i and send to the other party:
        let s1 = EphemeralKey::sign(
            &party1_ephemeral_key,
            &party1_h_0,
            &party1_key,
            &party1_key_agg.hash,
        );
        let s2 = EphemeralKey::sign(
            &party2_ephemeral_key,
            &party2_h_0,
            &party2_key,
            &party2_key_agg.hash,
        );

        let r = party1_ephemeral_key.keypair.public_key.x_coor().unwrap();

        assert!(verify_partial(
            &ECScalar::from(&s1),
            &r,
            &ECScalar::from(&party1_h_0),
            &ECScalar::from(&party1_key_agg.hash),
            &party1_key.public_key
        )
            .is_ok());

        // signature s:
        let (r, s) = EphemeralKey::add_signature_parts(s1, &s2, &party1_r_tag);

        // verify:
        assert!(verify(&s, &r, &party1_key_agg.apk, &message, is_musig,).is_ok())
    }

    #[test]
    fn test_schnorr_one_party() {
        let is_musig = false;
        let message: [u8; 4] = [79, 77, 69, 82];
        let party1_key = KeyPair::create();
        // let party1_key = KeyPair::create_from_private_key(&BigInt::from(259));
        let party1_ephemeral_key = EphemeralKey::create_from_private_key(&party1_key, &message);

        // compute c = H0(Rtag || apk || message)
        let party1_h_0 = EphemeralKey::hash_0(
            &party1_ephemeral_key.keypair.public_key,
            &party1_key.public_key,
            &message,
            is_musig,
        );

        let s_tag = EphemeralKey::sign(
            &party1_ephemeral_key,
            &party1_h_0,
            &party1_key,
            &BigInt::from(1),
        );

        // signature s:
        let (R, s) = EphemeralKey::add_signature_parts(
            s_tag,
            &BigInt::from(0),
            &party1_ephemeral_key.keypair.public_key,
        );
        // verify:
        assert!(verify(&s, &R, &party1_key.public_key, &message, is_musig).is_ok());
    }

    //this test works only for curvesecp256k1
    #[test]
    fn test_schnorr_bip_test_vector_2() {
        let private_key_raw = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF";
        //let public_key_raw =  "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B";
        let message_raw = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89";

        let is_musig = false;
        let message = hex::decode(message_raw).unwrap();
        let party1_key = KeyPair::create_from_private_key(
            &BigInt::from_str_radix(&private_key_raw, 16).unwrap(),
        );
        let party1_ephemeral_key = EphemeralKey::create_from_private_key(&party1_key, &message);

        // compute c = H0(Rtag || apk || message)
        let party1_h_0 = EphemeralKey::hash_0(
            &party1_ephemeral_key.keypair.public_key,
            &party1_key.public_key,
            &message,
            is_musig,
        );

        // compute partial signature s_i and send to the other party:
        let s_tag = EphemeralKey::sign(
            &party1_ephemeral_key,
            &party1_h_0,
            &party1_key,
            &BigInt::from(1),
        );

        // signature s:
        let (R, s) = EphemeralKey::add_signature_parts(
            s_tag,
            &BigInt::from(0),
            &party1_ephemeral_key.keypair.public_key,
        );

        let test_vector_R =
            "2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d".to_string();
        let test_vector_s =
            "1e51a22ccec35599b8f266912281f8365ffc2d035a230434a1a64dc59f7013fd".to_string();
        let sig_R = R.to_str_radix(16);
        let sig_s = s.to_str_radix(16);
        assert_eq!(test_vector_R, sig_R);
        assert_eq!(test_vector_s, sig_s);
        // verify:
        assert!(verify(&s, &R, &party1_key.public_key, &message, is_musig).is_ok())
    }
}