#![allow(non_snake_case)]
#[allow(unused_doc_comments)]
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
use Error::{self, InvalidKey, InvalidSS, InvalidSig};

use curv::arithmetic::traits::*;

use curv::elliptic::curves::traits::*;

use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{BigInt, FE, GE};

const SECURITY: usize = 256;

pub struct Keys {
    pub u_i: FE,
    pub y_i: GE,
    pub party_index: usize,
}

pub struct KeyGenBroadcastMessage1 {
    com: BigInt,
}

#[derive(Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}
#[derive(Clone)]
pub struct SharedKeys {
    pub y: GE,
    pub x_i: FE,
}

impl Keys {
    pub fn phase1_create(index: usize) -> Keys {
        let u: FE = ECScalar::new_random();
        let y = &ECPoint::generator() * &u;

        Keys {
            u_i: u,
            y_i: y,
            party_index: index.clone(),
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenBroadcastMessage1, BigInt) {
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &self.y_i.bytes_compressed_to_big_int(),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 { com };
        (bcm1, blind_factor)
    }

    pub fn phase1_verify_com_phase2_distribute(
        &self,
        params: &Parameters,
        blind_vec: &Vec<BigInt>,
        y_vec: &Vec<GE>,
        bc1_vec: &Vec<KeyGenBroadcastMessage1>,
        parties: &[usize],
    ) -> Result<(VerifiableSS, Vec<FE>, usize), Error> {
        // test length:
        assert_eq!(blind_vec.len(), params.share_count);
        assert_eq!(bc1_vec.len(), params.share_count);
        assert_eq!(y_vec.len(), params.share_count);
        // test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::create_commitment_with_user_defined_randomness(
                    &y_vec[i].bytes_compressed_to_big_int(),
                    &blind_vec[i],
                ) == bc1_vec[i].com
            })
            .all(|x| x == true);

        let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
            params.threshold,
            params.share_count,
            &self.u_i,
            parties,
        );
        match correct_key_correct_decom_all {
            true => Ok((vss_scheme, secret_shares, self.party_index.clone())),
            false => Err(InvalidKey),
        }
    }

    pub fn phase2_verify_vss_construct_keypair(
        &self,
        params: &Parameters,
        y_vec: &Vec<GE>,
        secret_shares_vec: &Vec<FE>,
        vss_scheme_vec: &Vec<VerifiableSS>,
        index: &usize,
    ) -> Result<SharedKeys, Error> {
        assert_eq!(y_vec.len(), params.share_count);
        assert_eq!(secret_shares_vec.len(), params.share_count);
        assert_eq!(vss_scheme_vec.len(), params.share_count);

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], &index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0] == y_vec[i]
            })
            .all(|x| x == true);

        match correct_ss_verify {
            true => {
                let mut y_vec_iter = y_vec.iter();
                let y0 = y_vec_iter.next().unwrap();
                let y = y_vec_iter.fold(y0.clone(), |acc, x| acc + x);
                let x_i = secret_shares_vec.iter().fold(FE::zero(), |acc, x| acc + x);
                Ok(SharedKeys { y, x_i })
            }
            false => Err(InvalidSS),
        }
    }

    // remove secret shares from x_i for parties that are not participating in signing
    pub fn update_shared_key(
        shared_key: &SharedKeys,
        parties_in: &[usize],
        secret_shares_vec: &Vec<FE>,
    ) -> SharedKeys {
        let mut new_xi: FE = FE::zero();
        for i in 0..secret_shares_vec.len() {
            if parties_in.iter().find(|&&x| x == i).is_some() {
                new_xi = new_xi + &secret_shares_vec[i]
            }
        }
        SharedKeys {
            y: shared_key.y.clone(),
            x_i: new_xi,
        }
    }
}

mod test;

pub struct LocalSig {
    gamma_i: FE,
    e: FE,
}

impl LocalSig {
    pub fn compute(
        message: &[u8],
        local_ephemaral_key: &SharedKeys,
        local_private_key: &SharedKeys,
    ) -> LocalSig {
        let beta_i = local_ephemaral_key.x_i.clone();
        let alpha_i = local_private_key.x_i.clone();

        let e_bn = HSha256::create_hash(&[
            &local_ephemaral_key.y.bytes_compressed_to_big_int(),
            &local_private_key.y.bytes_compressed_to_big_int(),
            &BigInt::from(message),
        ]);
        let e: FE = ECScalar::from(&e_bn);
        let gamma_i = beta_i + e.clone() * alpha_i;
        //   let gamma_i = e.clone() * alpha_i ;

        LocalSig { gamma_i, e }
    }

    // section 4.2 step 3
    #[allow(unused_doc_comments)]
    pub fn verify_local_sigs(
        gamma_vec: &Vec<LocalSig>,
        parties_index_vec: &[usize],
        vss_private_keys: &Vec<VerifiableSS>,
        vss_ephemeral_keys: &Vec<VerifiableSS>,
    ) -> Result<(VerifiableSS), Error> {
        ///parties_index_vec is a vector with indices of the parties that are participating and provided gamma_i for this step
        /// test that enough parties are in this round
        assert!(parties_index_vec.len() > vss_private_keys[0].parameters.threshold);

        /// Vec of joint commitments:
        /// n' = num of signers, n - num of parties in keygen
        /// [com0_eph_0,... ,com0_eph_n', e*com0_kg_0, ..., e*com0_kg_n ;
        /// ...  ;
        /// comt_eph_0,... ,comt_eph_n', e*comt_kg_0, ..., e*comt_kg_n ]
        let comm_vec = (0..vss_private_keys[0].parameters.threshold + 1)
            .map(|i| {
                let mut key_gen_comm_i_vec = (0..vss_private_keys.len())
                    .map(|j| vss_private_keys[j].commitments[i].clone() * &gamma_vec[i].e)
                    .collect::<Vec<GE>>();
                let mut eph_comm_i_vec = (0..vss_ephemeral_keys.len())
                    .map(|j| vss_ephemeral_keys[j].commitments[i].clone())
                    .collect::<Vec<GE>>();
                key_gen_comm_i_vec.append(&mut eph_comm_i_vec);
                let mut comm_i_vec_iter = key_gen_comm_i_vec.iter();
                let comm_i_0 = comm_i_vec_iter.next().unwrap();
                comm_i_vec_iter.fold(comm_i_0.clone(), |acc, x| acc + x)
            })
            .collect::<Vec<GE>>();

        let vss_sum = VerifiableSS {
            parameters: vss_ephemeral_keys[0].parameters.clone(),
            commitments: comm_vec,
        };

        let g: GE = GE::generator();
        let correct_ss_verify = (0..parties_index_vec.len())
            .map(|i| {
                let gamma_i_g = &g * &gamma_vec[i].gamma_i;
                vss_sum
                    .validate_share_public(&gamma_i_g, &(parties_index_vec[i] + 1))
                    .is_ok()
            })
            .collect::<Vec<bool>>();

        match correct_ss_verify.iter().all(|x| x.clone() == true) {
            true => Ok(vss_sum),
            false => Err(InvalidSS),
        }
    }
}

pub struct Signature {
    sigma: FE,
    v: GE,
}

impl Signature {
    pub fn generate(
        vss_sum_local_sigs: &VerifiableSS,
        local_sig_vec: &Vec<LocalSig>,
        parties_index_vec: &[usize],
        v: GE,
    ) -> Signature {
        let gamma_vec = (0..parties_index_vec.len())
            .map(|i| local_sig_vec[i].gamma_i.clone())
            .collect::<Vec<FE>>();
        let reconstruct_limit = vss_sum_local_sigs.parameters.threshold.clone() + 1;
        let sigma = vss_sum_local_sigs.reconstruct(
            &parties_index_vec[0..reconstruct_limit.clone()],
            &gamma_vec[0..reconstruct_limit.clone()],
        );
        Signature { sigma, v }
    }

    pub fn verify(&self, message: &[u8], pubkey_y: &GE) -> Result<(), Error> {
        let e_bn = HSha256::create_hash(&[
            &self.v.bytes_compressed_to_big_int(),
            &pubkey_y.bytes_compressed_to_big_int(),
            &BigInt::from(message),
        ]);
        let e: FE = ECScalar::from(&e_bn);

        let g: GE = GE::generator();
        let sigma_g = g * &self.sigma;
        let e_y = pubkey_y * &e;
        let e_y_plus_v = e_y + &self.v;

        if e_y_plus_v == sigma_g {
            Ok(())
        } else {
            Err(InvalidSig)
        }
    }
}
