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
/// Simple Schnorr {2,2}-Signatures (https://eprint.iacr.org/2018/068.pdf, https://eprint.iacr.org/2018/483.pdf subsection 5.1)

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
use ::elliptic::point::{Point};
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;
use cryptographic_primitives::commitments::hash_commitment;
use arithmetic::traits::Modulo;
#[allow(dead_code)]
#[derive(Debug)]
pub struct Party1KeyGen {
    pub party1_public_key: PK,
    party1_private_key: SK
}
#[allow(dead_code)]
#[derive(Debug)]
pub struct Party1KeyAgg{
    pub apk: PK,
    pub hash1_a1: BigInt

}

#[allow(dead_code)]
#[derive(Debug)]
pub struct  Party1EphemeralKey{
    pub party1_ephemeral_public_key: PK,
    party1_ephemeral_private_key: SK,
    pub party1_Eph_key_comm: BigInt,
    pub blind_factor : BigInt
}


impl Party1KeyGen {
    pub fn key_gen(ec_context: &EC) -> Party1KeyGen {
        let mut party1_public_key = PK::to_key(&ec_context, &EC::get_base_point());
        let party1_private_key = party1_public_key.randomize(&ec_context);
        Party1KeyGen{
            party1_public_key,
            party1_private_key
        }

    }
}

impl Party1KeyAgg{
    pub fn key_aggregation(ec_context: &EC, party1_pk: &PK, party2_pk: &PK) -> Party1KeyAgg {

        let hash1_a1 = HSha256::create_hash(
            vec![&BigInt::from(1), &party1_pk.to_point().x, &party1_pk.to_point().x, &party2_pk.to_point().x]);
        let mut a1 = *party1_pk;
        a1.mul_assign(ec_context, &SK::from_big_int(ec_context, &hash1_a1));

        let hash2 = HSha256::create_hash(
            vec![&BigInt::from(1), &party2_pk.to_point().x, &party1_pk.to_point().x, &party2_pk.to_point().x]);
        let mut a2 = *party2_pk;
        a2.mul_assign(ec_context, &SK::from_big_int(ec_context, &hash2));

        let apk = a2.combine(ec_context, &a1).unwrap();
        Party1KeyAgg{
            apk,
            hash1_a1
        }
    }
}


impl Party1EphemeralKey{

   pub fn create(ec_context: &EC) -> Party1EphemeralKey{
        let mut party1_ephemeral_public_key = PK::to_key(&ec_context, &EC::get_base_point());
        let party1_ephemeral_private_key = party1_ephemeral_public_key.randomize(&ec_context);
        let (party1_Eph_key_comm, blind_factor) = HashCommitment::create_commitment(&party1_ephemeral_public_key.to_point().x);
        Party1EphemeralKey{
            party1_ephemeral_public_key,
            party1_ephemeral_private_key,
            party1_Eph_key_comm,
            blind_factor
        }
    }

    pub fn test_party2_com(R2_to_test: &PK, blind_factor: &BigInt, comm: &BigInt) -> bool{
        let computed_comm = &HashCommitment::create_commitment_with_user_defined_randomness(&R2_to_test.to_point().x,blind_factor);
        computed_comm == comm
    }

    pub fn add_ephemeral_pub_keys(ec_context: &EC, R1: &PK, R2: &PK) -> PK{
        R1.combine(ec_context, R2).unwrap()
    }

    pub fn hash_0(R_hat: &PK, apk: &PK, message:  &[u8] ) -> BigInt{
         HSha256::create_hash(
            vec![&BigInt::from(0),&R_hat.to_point().x, &apk.to_point().x, &BigInt::from(message)])
    }

    pub fn sign1(r1: &Party1EphemeralKey, c: &BigInt, x1: &Party1KeyGen, a1: &BigInt) -> BigInt{

        BigInt::mod_add(
            &r1.party1_ephemeral_private_key.to_big_int(), &BigInt::mod_mul(
                c, &BigInt::mod_mul(
                    &x1.party1_private_key.to_big_int(),a1,&EC::get_q())
                , &EC::get_q()), &EC::get_q())

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

       if sG ==  R_tag.combine(ec_context,&cY).unwrap(){
            Ok(())
        } else {
            Err(ProofError)
        }

    }


}




