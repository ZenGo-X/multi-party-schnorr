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

//! Schnorr {n,n}-Signatures based on Accountable-Subgroup Multisignatures
//!
//See (https://pdfs.semanticscholar.org/6bf4/f9450e7a8e31c106a8670b961de4735589cf.pdf)
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};

use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::*;
use protocols::multisig;

// I is a private key and public key keypair, X is a commitment of the form X = xG used only in key generation (see p11 in the paper)
#[derive(Debug, Clone)]
pub struct Keys {
    pub I: KeyPair,
    pub X: KeyPair,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: GE,
    private_key: FE,
}

impl KeyPair {
    pub fn create() -> KeyPair {
        let ec_point: GE = ECPoint::generator();
        let private_key: FE = ECScalar::new_random();
        let public_key = ec_point * &private_key;
        KeyPair {
            public_key,
            private_key,
        }
    }

    pub fn create_from_private_key(private_key: FE) -> KeyPair {
        let g: GE = ECPoint::generator();
        let public_key = g * &private_key;

        KeyPair {
            public_key,
            private_key,
        }
    }

    pub fn update_key_pair(&mut self, to_add: FE) {
        self.private_key = to_add + &self.private_key;
        let g: GE = ECPoint::generator();
        self.public_key = g * &self.private_key;
    }
}

impl Keys {
    pub fn create() -> Keys {
        let I = KeyPair::create();
        let X = KeyPair::create();
        Keys { I, X }
    }

    pub fn create_from_private_keys(priv_I: FE, priv_X: FE) -> Keys {
        let I = KeyPair::create_from_private_key(priv_I);
        let X = KeyPair::create_from_private_key(priv_X);
        Keys { I, X }
    }

    pub fn create_from(secret_share: FE) -> Keys {
        let I = KeyPair::create_from_private_key(secret_share);
        let X = KeyPair::create();
        Keys { I, X }
    }

    pub fn create_signing_key(keys: &Keys, eph_key: &EphKey) -> Keys {
        Keys {
            I: keys.I.clone(),
            X: eph_key.eph_key_pair.clone(),
        }
    }

    pub fn broadcast(keys: Keys) -> Vec<GE> {
        return vec![keys.I.public_key, keys.X.public_key];
    }

    pub fn collect_and_compute_challenge(ix_vec: &[Vec<GE>]) -> FE {
        let concat_vec = ix_vec.iter().fold(Vec::new(), |mut acc, x| {
            acc.extend_from_slice(x);
            acc
        });
        let ref_vec = concat_vec.iter().collect::<Vec<&GE>>();
        multisig::hash_4(&ref_vec[..])
    }

    pub fn to_encrypted_segment(
        &self,
        segment_size: &usize,
        num_of_segments: usize,
        pub_ke_y: &GE,
        g: &GE,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(
            &self.I.private_key,
            &segment_size,
            num_of_segments,
            pub_ke_y,
            g,
        )
    }
}

pub fn partial_sign(keys: &Keys, e: FE) -> FE {
    e * &keys.I.private_key + &keys.X.private_key
}

pub fn verify<'a>(I: &GE, sig: &Signature, e: &FE) -> Result<(), &'a str> {
    let X = &sig.X;
    let y = &sig.y;
    let base_point: GE = ECPoint::generator();
    let yG = base_point * y;
    let eI = I * e;
    let X_plus_eI = X + &eI;
    if yG == X_plus_eI {
        Ok(())
    } else {
        Err("error verification")
    }
}

fn hash_4(key_list: &[&GE]) -> FE {
    let four_fe: FE = ECScalar::from(&BigInt::from(4));
    let base_point: GE = ECPoint::generator();
    let four_ge = base_point * four_fe;
    let mut four_ge_vec = vec![&four_ge];
    four_ge_vec.extend(key_list);
    HSha256::create_hash_from_ge(&four_ge_vec)
}

pub struct EphKey {
    pub eph_key_pair: KeyPair,
}

impl EphKey {
    //signing step 1
    pub fn gen_commit() -> EphKey {
        let eph_key_pair = KeyPair::create();
        EphKey { eph_key_pair }
    }
    //signing steps 2,3
    // we treat S as a list of public keys and compute a sum.
    pub fn compute_joint_comm_e(
        mut pub_key_vec: Vec<GE>,
        mut eph_pub_key_vec: Vec<GE>,
        message: &[u8],
    ) -> (GE, GE, FE) {
        let first_pub_key = pub_key_vec.remove(0);
        let sum_pub = pub_key_vec
            .iter()
            .fold(first_pub_key, |acc, x| acc.add_point(&x.get_element()));
        let first_eph_pub_key = eph_pub_key_vec.remove(0);
        let sum_pub_eph = eph_pub_key_vec
            .iter()
            .fold(first_eph_pub_key, |acc, x| acc.add_point(&x.get_element()));
        //TODO: maybe there is a better way?
        let m_fe: FE = ECScalar::from(&BigInt::from(message));
        let base_point: GE = GE::generator();
        let m_ge = base_point.scalar_mul(&m_fe.get_element());
        let e = multisig::hash_4(&[&sum_pub_eph, &m_ge, &sum_pub]);
        (sum_pub, sum_pub_eph, e)
    }

    pub fn partial_sign(&self, local_keys: &KeyPair, es: FE) -> FE {
        es * &local_keys.private_key + &self.eph_key_pair.private_key
    }

    pub fn add_signature_parts(sig_vec: Vec<FE>) -> FE {
        let mut sig_vec_c = sig_vec;
        let first_sig = sig_vec_c.remove(0);

        sig_vec_c
            .iter()
            .fold(first_sig, |acc, x| acc.add(&x.get_element()))
    }
}

pub struct Signature {
    X: GE,
    y: FE,
}

impl Signature {
    pub fn set_signature(X: &GE, y: &FE) -> Signature {
        Signature {
            X: X.clone(),
            y: y.clone(),
        }
    }
}

mod test;
