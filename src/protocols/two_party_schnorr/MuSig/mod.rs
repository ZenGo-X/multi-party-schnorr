/*
    Multi-party ECSDA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECSDA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

//! Simple Schnorr {2,2}-Signatures 
//! 
//! See https://eprint.iacr.org/2018/068.pdf, https://eprint.iacr.org/2018/483.pdf subsection 5.1

use ::BigInt;

const SECURITY_BITS : usize = 256;

use elliptic::curves::traits::*;

use arithmetic::traits::Samplable;

use cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptographic_primitives::proofs::ProofError;

use cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptographic_primitives::commitments::traits::Commitment;

// TODO: remove the next line when unit test will be done

use ::EC;
use ::PK;
use ::SK;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;
use cryptographic_primitives::commitments::hash_commitment;
use arithmetic::traits::Modulo;

#[derive(Debug)]
pub struct KeyPair {
    pub public_key: PK,
    private_key: SK
}

impl KeyPair {
    pub fn create(ec_context: &EC) -> KeyPair {
        let mut public_key = PK::to_key(&ec_context, &EC::get_base_point());
        let private_key = public_key.randomize(&ec_context);
        KeyPair {
            public_key,
            private_key
        }
    }
}

#[derive(Debug)]
pub struct KeyAgg {
    pub apk: PK,
    pub hash: BigInt
}

impl KeyAgg {
    pub fn key_aggregation(ec_context: &EC, my_pk: &PK, other_pk: &PK) -> KeyAgg {
        let hash = HSha256::create_hash(
            vec![&BigInt::from(1), &my_pk.to_point().x, &my_pk.to_point().x, &other_pk.to_point().x]);
        let mut a1 = *my_pk;
        a1.mul_assign(ec_context, &SK::from_big_int(ec_context, &hash));

        let hash2 = HSha256::create_hash(
            vec![&BigInt::from(1), &other_pk.to_point().x, &my_pk.to_point().x, &other_pk.to_point().x]);
        let mut a2 = *other_pk;
        a2.mul_assign(ec_context, &SK::from_big_int(ec_context, &hash2));
        let apk = a2.combine(ec_context, &a1).unwrap();
        KeyAgg {
            apk,
            hash
        }
    }

    pub fn key_aggregation_n(ec_context: &EC, pks: &Vec<PK>, party_index: &usize) -> KeyAgg {

        let bn_1 = BigInt::from(1);
        let mut x_coor_vec: Vec<BigInt> = (0..pks.len()).into_iter().map(|i| pks[i].to_point().x).collect();
        let hash_vec: Vec<BigInt> = x_coor_vec.iter().map(|pk|{
            let mut vec = Vec::new();
            vec.push(&bn_1);
            vec.push( pk);
            for i in 0..pks.len(){vec.push(&x_coor_vec[i]);}
            HSha256::create_hash(vec)
        }).collect();

        let apk_vec: Vec<PK> = pks.iter().zip(&hash_vec).map(|(pk, hash)|{
            let mut a_i = pk.clone();
            a_i.mul_assign(ec_context, &SK::from_big_int(ec_context, &hash));
            a_i
        }).collect();

        let mut apk_vec_2_n = apk_vec.clone();
        let mut pk1 = apk_vec_2_n.remove(0);
        let sum = apk_vec_2_n.iter().fold(pk1, |acc,pk|  acc.combine(&ec_context,pk).unwrap());

        KeyAgg {
            apk: sum,
            hash: hash_vec[*party_index].clone()
        }

    }
}

#[derive(Debug)]
pub struct EphemeralKey {
    pub keypair: KeyPair,
    pub commitment: BigInt,
    pub blind_factor: BigInt
}

impl EphemeralKey {

    pub fn create(ec_context: &EC) -> EphemeralKey {
        let keypair = KeyPair::create(ec_context);
        let (commitment, blind_factor) = HashCommitment::create_commitment(&keypair.public_key.to_point().x);
        EphemeralKey {
            keypair,
            commitment,
            blind_factor
        }
    }

    pub fn test_com(r_to_test: &PK, blind_factor: &BigInt, comm: &BigInt) -> bool{
        let computed_comm = &HashCommitment::create_commitment_with_user_defined_randomness(&r_to_test.to_point().x,blind_factor);
        computed_comm == comm
    }

    pub fn add_ephemeral_pub_keys(ec_context: &EC, R1: &PK, R2: &PK) -> PK {
        R1.combine(ec_context, R2).unwrap()
    }

    pub fn hash_0(R_hat: &PK, apk: &PK, message: &[u8]) -> BigInt{
        HSha256::create_hash(
            vec![&BigInt::from(0),&R_hat.to_point().x, &apk.to_point().x, &BigInt::from(message)])
    }

    pub fn add_signature_parts(s1: &BigInt, s2: &BigInt, Rtag: &PK) -> (PK, BigInt){
        (*Rtag, BigInt::mod_add(&s1, &s2,&EC::get_q()))
    }

    pub fn verify(ec_context: &EC, signature: &BigInt, R_tag: &PK, apk: &PK, message:  &[u8]) -> Result<(), ProofError>{
        let c = HSha256::create_hash(
            vec![&BigInt::from(0),&R_tag.to_point().x, &apk.to_point().x, &BigInt::from(message)]);
        let mut sG = PK::to_key(ec_context, &EC::get_base_point());

        let mut cY = *apk;
        cY.mul_assign(ec_context,&SK::from_big_int(ec_context, &c));
        sG.mul_assign(ec_context, &SK::from_big_int(ec_context, signature));

        if sG == R_tag.combine(ec_context,&cY).unwrap() {
            Ok(())
        } else {
            Err(ProofError)
        }
    }

    pub fn sign(r: &EphemeralKey, c: &BigInt, x: &KeyPair, a: &BigInt) -> BigInt{
        BigInt::mod_add(
            &r.keypair.private_key.to_big_int(), &BigInt::mod_mul(
                c, &BigInt::mod_mul(
                    &x.private_key.to_big_int(),a,&EC::get_q())
                , &EC::get_q()), &EC::get_q())
    }

}

pub mod party_two {

    use super::*;

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Party2KeyAgg{
        pub apk: PK,
        pub hash: BigInt

    }

    impl Party2KeyAgg{
        pub fn key_aggregation(ec_context: &EC, my_pk: &PK, other_pk: &PK) -> Party2KeyAgg {

            let hash = HSha256::create_hash(
                vec![&BigInt::from(1), &other_pk.to_point().x, &my_pk.to_point().x, &other_pk.to_point().x]);
            let mut a1 = *other_pk;
            a1.mul_assign(ec_context, &SK::from_big_int(ec_context, &hash));

            let hash2 = HSha256::create_hash(
                vec![&BigInt::from(1), &my_pk.to_point().x, &my_pk.to_point().x, &other_pk.to_point().x]);
            let mut a2 = *my_pk;
            a2.mul_assign(ec_context, &SK::from_big_int(ec_context, &hash2));

            let apk = a2.combine(ec_context, &a1).unwrap();
            
            Party2KeyAgg{
                apk,
                hash
            }
        }
    }


    
}

mod test;