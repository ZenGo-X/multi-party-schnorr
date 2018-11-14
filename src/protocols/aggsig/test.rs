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

#[cfg(test)]
mod tests {
    use cryptography_utils::BigInt;
    use cryptography_utils::GE;
    use protocols::aggsig::{verify, EphemeralKey, KeyAgg, KeyPair};
    extern crate hex;

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
        assert!(verify(&s, &R, &party1_key.public_key, &message, is_musig).is_ok())
    }

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
