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

//! Two round Multisig Schnorr
//!
//! This is an implementation of the algorithm presented in https://eprint.iacr.org/2020/1261 (page 12).
//! The number of shares Nv is set to 2 which is claimed to be secure assuming random oracle model and algebraic group model


use curv::{BigInt, FE, GE};

use curv::cryptographic_primitives::proofs::*;
use curv::elliptic::curves::traits::*;

use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::*;

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::*;

#[warn(dead_code)]
const Nv: usize = 2;

#[derive(Debug,Clone)]
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


}

#[derive(Debug)]
pub struct KeyAgg {
    pub X_tilde: GE,
    pub a_i: BigInt,
}

impl KeyAgg {

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
                // the "L" part of the hash
            })
            .collect();

        let mut X_tilde_vec: Vec<GE> = pks
            .iter()
            .zip(&hash_vec)
            .map(|(pk, hash)| {
                let hash_t: FE = ECScalar::from(&hash);
                let pki: GE = pk.clone();
                pki.scalar_mul(&hash_t.get_element())
            })
            .collect();

        let pk1 = X_tilde_vec.remove(0);
        let sum = X_tilde_vec
            .iter()
            .fold(pk1, |acc, pk| acc.add_point(&pk.get_element()));

        KeyAgg {
            X_tilde: sum,
            a_i: hash_vec[party_index].clone(),
        }
    }
}

#[derive(Debug,Clone)]
pub struct EphemeralKey {
    pub keypair: KeyPair,
    pub commitment: BigInt,
    pub blind_factor: BigInt,
}




impl EphemeralKey {
    pub fn create_vec_from_private_key(x1: &KeyPair) -> Vec<EphemeralKey> {
        let mut EphermalKeys_vec: Vec<EphemeralKey> = vec![];
        for i in 0..Nv {
            let base_point: GE = ECPoint::generator();
            let hash_private_key_message =
                HSha256::create_hash(&[&x1.private_key.to_big_int(), &BigInt::from(i as i32)]);
            let ephemeral_private_key: FE = ECScalar::from(&hash_private_key_message);
            let ephemeral_public_key = base_point.scalar_mul(&ephemeral_private_key.get_element());
            let (commitment, blind_factor) = HashCommitment::create_commitment(
                &ephemeral_public_key.bytes_compressed_to_big_int(),
            );
            let eph_key = EphemeralKey {
                keypair: KeyPair {
                    public_key: ephemeral_public_key,
                    private_key: ephemeral_private_key,
                },
                commitment,
                blind_factor,
            };
            EphermalKeys_vec.push(eph_key);
        }
        EphermalKeys_vec
     }

}



#[derive(Debug, Clone)]
pub struct State {
    pub keypair: KeyPair,
    pub ephk_vec: Vec<EphemeralKey>,
}




impl State {
    fn add_ephemeral_keys(&self, msg_vec: &[Vec<GE>]) -> Vec<GE> {
        let mut R_j_vec: Vec<GE> = vec![];
        for j in 0..Nv {
            let pk_0j = self.ephk_vec[j].keypair.public_key;
            let R_j: GE = msg_vec.
                iter().
                fold(pk_0j, |acc, ephk| acc.add_point(&ephk.get(j).unwrap().get_element()));
            R_j_vec.push(R_j);
        }
        R_j_vec
    }
}

#[derive(Debug, Clone)]
pub struct StatePrime {
    pub R: GE,
    pub s_i: FE,
}

pub fn sign(x: KeyPair) -> ( Vec<GE>, State) {
    let ephk_vec = EphemeralKey::create_vec_from_private_key(&x);
    let msg = ephk_vec
        .iter()
        .map(|eph_key| eph_key.keypair.public_key)
        .collect();
    (msg, State {keypair: x, ephk_vec: ephk_vec})
}


pub fn hash_sig(r_hat: &GE, X_tilde: &GE, message: &[u8]) -> BigInt {
    HSha256::create_hash(&[
        &BigInt::from(0),
        &r_hat.x_coor().unwrap(),
        &X_tilde.bytes_compressed_to_big_int(),
        &BigInt::from(message),
    ])
}

impl StatePrime {
    pub fn get_StatePrime(&self) -> &StatePrime {
        self
    }
}

     fn compute_signature_share(
         state: &State,
        b_coefficients: &Vec<BigInt>,
        c: &BigInt,
        x: &KeyPair,
        a: &BigInt,
    ) -> (FE, FE) {
        let c_fe: FE = ECScalar::from(c);
        let a_fe: FE = ECScalar::from(a);
        let lin_comb_ephemeral_i: FE = state.ephk_vec.
            iter().
            zip(b_coefficients).
            fold(ECScalar::zero(), |acc, (ephk,b)|
                acc + ephk.keypair.private_key * <FE as ECScalar<_>>::from(b));
        let s_fe = lin_comb_ephemeral_i.clone() + (c_fe * x.private_key.clone() * a_fe);
        (s_fe, lin_comb_ephemeral_i.clone())
    }





// compute global parameters: c, R, and the b's coefficients
pub fn compute_global_params(
    state:  &State,
    message: &[u8],
    pks: &Vec<GE>,
    msg_vec: Vec<Vec<GE>>,
    party_index: usize,
)->(BigInt, GE, Vec<BigInt>){
    let key_agg = KeyAgg::key_aggregation_n(&pks, party_index);
    let mut R_j_vec = state.add_ephemeral_keys(&msg_vec);
    let mut b_coefficients: Vec<BigInt> = Vec::new();
    b_coefficients.push(BigInt::from(1));
    for j in 1..Nv {
        let mut hnon_preimage: Vec<BigInt> = Vec::new();
        hnon_preimage.push(key_agg.X_tilde.bytes_compressed_to_big_int());
        for i in 0..Nv {
            hnon_preimage.push(R_j_vec[i].bytes_compressed_to_big_int());
        }
        hnon_preimage.push(BigInt::from(message));
        hnon_preimage.push(BigInt::from(j as i32));
        let b_j = HSha256::create_hash(&hnon_preimage.iter().collect::<Vec<_>>());
        b_coefficients.push(b_j);
    }
    let R_j0 = R_j_vec.remove(0);
    let mut b_coefficients_temp = b_coefficients.clone();
    let b_0 = b_coefficients_temp.remove(0);
    let R_0 = R_j0 * &<FE as ECScalar<_>>::from(&b_0);
    let R: GE = R_j_vec
        .iter()
        .zip(b_coefficients_temp.clone())
        .map(|(R_j, b_j)| R_j * &<FE as ECScalar<_>>::from(&b_j))
        .fold(R_0, |acc, R_j| acc.add_point(&R_j.get_element()));
    let c = hash_sig(&R, &key_agg.X_tilde, message);
    (c, R, b_coefficients)
}


    pub fn sign_prime(
       state: State,
        message: &[u8],
        pks: &Vec<GE>,
        msg_vec: Vec<Vec<GE>>,
        party_index: usize,
    ) -> (StatePrime, FE) {
        let key_agg = KeyAgg::key_aggregation_n(&pks, party_index);
        let (c, R, b_coefficients) =
            compute_global_params( &state, message, pks, msg_vec, party_index);
        let (s_i, r_i) = compute_signature_share(&state, &b_coefficients, &c, &state.keypair, &key_agg.a_i);
        (StatePrime{ R, s_i}, s_i)
    }

    pub fn sign_double_prime(StatePrime: StatePrime, msg_vec: &Vec<FE>) -> FE {
        let s_0 = StatePrime.s_i;
        msg_vec.iter().fold(s_0, |acc, s_i| acc + s_i)
    }



pub fn verify(
    signature: &FE,
    r_x: &BigInt,
    X_tilde: &GE,
    c: &BigInt, //musig_bit: bool,
) -> Result<(), ProofError> {
    let base_point: GE = ECPoint::generator();
    //let signature_fe: FE =ECScalar::from(signature);
    let sG = base_point.scalar_mul(&signature.get_element());
    let c: FE = ECScalar::from(&c);
    let cY = X_tilde.scalar_mul(&c.get_element());
    let sG = sG.sub_point(&cY.get_element());
    if sG.x_coor().unwrap().to_hex() == r_x.to_hex() {
        Ok(())
    } else {
        Err(ProofError)
    }
}


#[cfg(test)]
mod tests {
    use curv::{BigInt, FE, GE};
    use protocols::aggsig::musig_two_rounds::*;

    extern crate hex;

    use curv::elliptic::curves::traits::*;

    #[test]
    fn test_multiparty_signing_for_two_parties() {
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = KeyPair::create();
        let party2_key = KeyPair::create();

        // round 1: send commitments to ephemeral public keys
        let party1_ephemeral_keys = EphemeralKey::create_vec_from_private_key(&party1_key);
        let party2_ephemeral_keys = EphemeralKey::create_vec_from_private_key(&party2_key);
        let mut vec_r_1 = vec![
            party1_ephemeral_keys[0].keypair.public_key,
            party1_ephemeral_keys[1].keypair.public_key,
        ];
        let mut vec_r_2 = vec![
            party2_ephemeral_keys[0].keypair.public_key,
            party2_ephemeral_keys[1].keypair.public_key,
        ];

        // compute X_tilde:
        let mut pks: Vec<GE> = Vec::new();
        pks.push(party1_key.public_key.clone());
        pks.push(party2_key.public_key.clone());

        let party1_key_agg = KeyAgg::key_aggregation_n(&pks, 0);
        let party2_key_agg = KeyAgg::key_aggregation_n(&pks, 1);


        assert_eq!(party1_key_agg.X_tilde, party2_key_agg.X_tilde);
        let (party_1_msg,mut party_1_state) = sign(party1_key);
        let (party_2_msg,mut party_2_state) = sign(party2_key);

        let party1_received_msg = vec![Vec::from(party_2_msg)];
        let party2_received_msg = vec![Vec::from(party_1_msg)];

        // each party computes the vector (R_11+R_12,R_21+R_22):
        let R_vec_by_party_1: Vec<GE> = party_1_state.add_ephemeral_keys(&party1_received_msg);
        let R_vec_by_party_2: Vec<GE> = party_2_state.add_ephemeral_keys(&party2_received_msg);


        assert_eq!(R_vec_by_party_1, R_vec_by_party_2);
        let (party_1_StatePrime, s_1) =
            sign_prime(party_1_state.clone(), &message, &pks, party1_received_msg.clone(), 0);
        let (party_2_StatePrime, s_2) =
            sign_prime(party_2_state.clone(), &message, &pks, party2_received_msg.clone(), 1);
        let base_point: GE = ECPoint::generator();

        //  Each party computes R = R1 + R2
        let (c_party_1,R_party_1,_) =
            compute_global_params(&party_1_state.clone(), &message, &pks,party1_received_msg.clone(),0);
        let (c_party_2,R_party_2,_)  =
            compute_global_params(&party_2_state.clone(), &message, &pks,party2_received_msg.clone(),1);
        assert_eq!(R_party_1, R_party_2);
        assert_eq!(c_party_1, c_party_2);
        let R = R_party_1;
        let c = c_party_1;

        //add signature shares
        let s_total_1 = sign_double_prime(party_1_StatePrime, &vec![s_2]);
        let s_total_2 = sign_double_prime(party_2_StatePrime, &vec![s_1]);
        //verify that both parties computed the same signature
        assert_eq!(s_total_1, s_total_2);
        let s = s_total_1;

        // verification that the signature is computed correctly
        assert!(verify(&s, &R.x_coor().unwrap(), &party1_key_agg.X_tilde, &c).is_ok());

    }
}
