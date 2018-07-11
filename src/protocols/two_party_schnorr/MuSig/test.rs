#[cfg(test)]
mod tests {
    use ::EC;
    use ::protocols::two_party_schnorr::MuSig::party_one;
    use ::protocols::two_party_schnorr::MuSig::party_two;
   // use protocols::two_party_ecdsa::lindell_2017_keygen::*;

    #[test]

    fn test_two_party_signing(){
        let ec_context = EC::new();
        let message: [u8; 4] = [79, 77, 69, 82];
        let party1_key = party_one::Party1KeyGen::key_gen(&ec_context);
        let party2_key = party_two::Party2KeyGen::key_gen(&ec_context);

        //generate R1 and send com(R1) to p2:
        let party1_ephemeral_key = party_one::Party1EphemeralKey::create(&ec_context);
        //generate R2 and send com(R2) to p1:
        let party2_ephemeral_key = party_two::Party2EphemeralKey::create(&ec_context);
        // p1 release R1' and p2 test com(R1') = com(R1):
        assert!(party_one::Party1EphemeralKey::test_party2_com(&party2_ephemeral_key.party2_ephemeral_public_key,
                                                               &party2_ephemeral_key.blind_factor, &party2_ephemeral_key.party2_Eph_key_comm));
        // p2 release R2' and p1 test com(R2') = com(R2):
        assert!(party_two::Party2EphemeralKey::test_party1_com(&party1_ephemeral_key.party1_ephemeral_public_key,
                                                               &party1_ephemeral_key.blind_factor, &party1_ephemeral_key.party1_Eph_key_comm));

        // compute apk:
        let party1_key_agg = party_one::Party1KeyAgg::key_aggregation(&ec_context,&party1_key.party1_public_key,
                                                                      &party2_key.party2_public_key);
        let party2_key_agg = party_two::Party2KeyAgg::key_aggregation(&ec_context,&party1_key.party1_public_key,
                                                                  &party2_key.party2_public_key);
        assert_eq!(party1_key_agg.apk, party2_key_agg.apk);

        // compute R' = R1+R2:
        let party1_Rtag = party_one::Party1EphemeralKey::add_ephemeral_pub_keys(&ec_context,&party1_ephemeral_key.party1_ephemeral_public_key,
                                                                            &party2_ephemeral_key.party2_ephemeral_public_key);
        let party2_Rtag = party_two::Party2EphemeralKey::add_ephemeral_pub_keys(&ec_context,&party1_ephemeral_key.party1_ephemeral_public_key,
                                                                                &party2_ephemeral_key.party2_ephemeral_public_key);

        assert_eq!(party1_Rtag, party2_Rtag);

        // compute c = H0(Rtag || apk || message)
        let party1_H0 = party_one::Party1EphemeralKey::hash_0(&party1_Rtag, &party1_key_agg.apk, &message);
        let party2_H0 = party_two::Party2EphemeralKey::hash_0(&party2_Rtag, &party2_key_agg.apk, &message);
        assert_eq!(party1_H0, party2_H0);

        // compute partial signature s_i and send to the other party:
        let s1 = party_one::Party1EphemeralKey::sign1(&party1_ephemeral_key, &party1_H0, &party1_key, &party1_key_agg.hash1_a1);
        let s2 = party_two::Party2EphemeralKey::sign2(&party2_ephemeral_key, &party2_H0, &party2_key, &party2_key_agg.hash1_a2);

        // signature s:
        let (R, s) = party_one::Party1EphemeralKey::add_signature_parts(&s1, &s2, &party1_Rtag);

        // verify:
        assert!(party_one::Party1EphemeralKey::verify(&ec_context, &s, &R, &party1_key_agg.apk, &message).is_ok())

    }

}