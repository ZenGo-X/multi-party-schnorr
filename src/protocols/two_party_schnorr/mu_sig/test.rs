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
    use cryptography_utils::{EC, PK};
    use protocols::two_party_schnorr::mu_sig::party_two;
    use protocols::two_party_schnorr::mu_sig::{EphemeralKey, KeyAgg, KeyPair};

    #[test]
    fn test_two_party_signing() {
        let ec_context = EC::new();
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = KeyPair::create(&ec_context);
        let party2_key = KeyPair::create(&ec_context);

        // round 1: send commitments to ephemeral public keys
        let party1_ephemeral_key = EphemeralKey::create(&ec_context);
        let party2_ephemeral_key = EphemeralKey::create(&ec_context);
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
        let party1_key_agg =
            KeyAgg::key_aggregation(&ec_context, &party1_key.public_key, &party2_key.public_key);
        let party2_key_agg = party_two::Party2KeyAgg::key_aggregation(
            &ec_context,
            &party1_key.public_key,
            &party2_key.public_key,
        );

        assert_eq!(party1_key_agg.apk, party2_key_agg.apk);

        // compute R' = R1+R2:
        let party1_r_tag = EphemeralKey::add_ephemeral_pub_keys(
            &ec_context,
            &party1_ephemeral_key.keypair.public_key,
            &party2_ephemeral_key.keypair.public_key,
        );

        let party2_r_tag = EphemeralKey::add_ephemeral_pub_keys(
            &ec_context,
            &party1_ephemeral_key.keypair.public_key,
            &party2_ephemeral_key.keypair.public_key,
        );

        assert_eq!(party1_r_tag, party2_r_tag);

        // compute c = H0(Rtag || apk || message)
        let party1_h_0 = EphemeralKey::hash_0(&party1_r_tag, &party1_key_agg.apk, &message);
        let party2_h_0 = EphemeralKey::hash_0(&party2_r_tag, &party2_key_agg.apk, &message);
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
        let (r, s) = EphemeralKey::add_signature_parts(&s1, &s2, &party1_r_tag);

        // verify:
        assert!(EphemeralKey::verify(&ec_context, &s, &r, &party1_key_agg.apk, &message).is_ok())
    }

    #[test]
    fn test_multiparty_signing_for_two_parties() {
        let ec_context = EC::new();
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = KeyPair::create(&ec_context);
        let party2_key = KeyPair::create(&ec_context);

        // round 1: send commitments to ephemeral public keys
        let party1_ephemeral_key = EphemeralKey::create(&ec_context);
        let party2_ephemeral_key = EphemeralKey::create(&ec_context);
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
        let mut pks: Vec<PK> = Vec::new();
        pks.push(party1_key.public_key.clone());
        pks.push(party2_key.public_key.clone());
        let party1_key_agg = KeyAgg::key_aggregation_n(&ec_context, &pks, &0);
        let party2_key_agg = KeyAgg::key_aggregation_n(&ec_context, &pks, &1);
        assert_eq!(party1_key_agg.apk, party2_key_agg.apk);

        // compute R' = R1+R2:
        let party1_r_tag = EphemeralKey::add_ephemeral_pub_keys(
            &ec_context,
            &party1_ephemeral_key.keypair.public_key,
            &party2_ephemeral_key.keypair.public_key,
        );

        let party2_r_tag = EphemeralKey::add_ephemeral_pub_keys(
            &ec_context,
            &party1_ephemeral_key.keypair.public_key,
            &party2_ephemeral_key.keypair.public_key,
        );

        assert_eq!(party1_r_tag, party2_r_tag);

        // compute c = H0(Rtag || apk || message)
        let party1_h_0 = EphemeralKey::hash_0(&party1_r_tag, &party1_key_agg.apk, &message);
        let party2_h_0 = EphemeralKey::hash_0(&party2_r_tag, &party2_key_agg.apk, &message);
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
        let (r, s) = EphemeralKey::add_signature_parts(&s1, &s2, &party1_r_tag);

        // verify:
        assert!(EphemeralKey::verify(&ec_context, &s, &r, &party1_key_agg.apk, &message).is_ok())
    }
}
