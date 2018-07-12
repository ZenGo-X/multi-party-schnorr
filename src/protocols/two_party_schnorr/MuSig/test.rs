#[cfg(test)]
mod tests {
    use ::EC;
    use ::protocols::two_party_schnorr::MuSig::{KeyPair, KeyAgg, EphemeralKey};
    use ::protocols::two_party_schnorr::MuSig::party_two;
   // use protocols::two_party_ecdsa::lindell_2017_keygen::*;

    #[test]

    fn test_two_party_signing(){
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
            party2_commitment));
        // p2 release R2' and p1 test com(R2') = com(R2):
        assert!(EphemeralKey::test_com(
            &party1_ephemeral_key.keypair.public_key,
            &party1_ephemeral_key.blind_factor,
            party1_commitment));

        // compute apk:
        let party1_key_agg = KeyAgg::key_aggregation(
            &ec_context,
            &party1_key.public_key,
            &party2_key.public_key);
        let party2_key_agg = party_two::Party2KeyAgg::key_aggregation(
            &ec_context,
            &party1_key.public_key,
            &party2_key.public_key);

        assert_eq!(party1_key_agg.apk, party2_key_agg.apk);

        // compute R' = R1+R2:
        let party1_Rtag = EphemeralKey::add_ephemeral_pub_keys(
            &ec_context,
            &party1_ephemeral_key.keypair.public_key,
            &party2_ephemeral_key.keypair.public_key);

        let party2_Rtag = EphemeralKey::add_ephemeral_pub_keys(
            &ec_context,
            &party1_ephemeral_key.keypair.public_key,
            &party2_ephemeral_key.keypair.public_key);

        assert_eq!(party1_Rtag, party2_Rtag);

        // compute c = H0(Rtag || apk || message)
        let party1_H0 = EphemeralKey::hash_0(&party1_Rtag, &party1_key_agg.apk, &message);
        let party2_H0 = EphemeralKey::hash_0(&party2_Rtag, &party2_key_agg.apk, &message);
        assert_eq!(party1_H0, party2_H0);

        // compute partial signature s_i and send to the other party:
        let s1 = EphemeralKey::sign(&party1_ephemeral_key, &party1_H0, &party1_key, &party1_key_agg.hash);
        let s2 = EphemeralKey::sign(&party2_ephemeral_key, &party2_H0, &party2_key, &party2_key_agg.hash);

        // signature s:
        let (R, s) = EphemeralKey::add_signature_parts(&s1, &s2, &party1_Rtag);

        // verify:
        assert!(EphemeralKey::verify(&ec_context, &s, &R, &party1_key_agg.apk, &message).is_ok())

    }

}