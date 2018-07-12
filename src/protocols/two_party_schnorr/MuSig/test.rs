#[cfg(test)]
mod tests {
    extern crate hex;
    use ::BigInt;
    use ::EC;
    use ::protocols::two_party_schnorr::MuSig::party_one;
    use ::protocols::two_party_schnorr::MuSig::party_two;
   // use protocols::two_party_ecdsa::lindell_2017_keygen::*;

    #[test]

    fn test_two_party_signing(){
        let is_musig = true;
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
        let party1_H0 = party_one::Party1EphemeralKey::hash_0(&party1_Rtag, &party1_key_agg.apk, &message, &is_musig);
        let party2_H0 = party_two::Party2EphemeralKey::hash_0(&party2_Rtag, &party2_key_agg.apk, &message);
        assert_eq!(party1_H0, party2_H0);

        // compute partial signature s_i and send to the other party:
        let s1 = party_one::Party1EphemeralKey::sign1(&party1_ephemeral_key, &party1_H0, &party1_key, &party1_key_agg.hash1_a1);
        let s2 = party_two::Party2EphemeralKey::sign2(&party2_ephemeral_key, &party2_H0, &party2_key, &party2_key_agg.hash1_a2);

        // signature s:
        let (R, s) = party_one::Party1EphemeralKey::add_signature_parts(&s1, &s2, &party1_Rtag);

        // verify:
        assert!(party_one::Party1EphemeralKey::verify(&ec_context, &s, &R, &party1_key_agg.apk, &message, &is_musig).is_ok())

    }

    #[test]

    fn test_two_party_signing_ephemeral_key_from_private(){
        let is_musig = true;
        let ec_context = EC::new();
        let message: [u8; 4] = [79, 77, 69, 82];
        let party1_key = party_one::Party1KeyGen::key_gen(&ec_context);
        let party2_key = party_two::Party2KeyGen::key_gen(&ec_context);

        //generate R1 and send com(R1) to p2:
        let party1_ephemeral_key = party_one::Party1EphemeralKey::create_from_private_key(&ec_context, &party1_key, &message);
        //generate R2 and send com(R2) to p1:
        let party2_ephemeral_key = party_two::Party2EphemeralKey::create_from_private_key(&ec_context, &party2_key, &message);
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
        let party1_H0 = party_one::Party1EphemeralKey::hash_0(&party1_Rtag, &party1_key_agg.apk, &message, &is_musig);
        let party2_H0 = party_two::Party2EphemeralKey::hash_0(&party2_Rtag, &party2_key_agg.apk, &message);
        assert_eq!(party1_H0, party2_H0);

        // compute partial signature s_i and send to the other party:
        let s1 = party_one::Party1EphemeralKey::sign1(&party1_ephemeral_key, &party1_H0, &party1_key, &party1_key_agg.hash1_a1);
        let s2 = party_two::Party2EphemeralKey::sign2(&party2_ephemeral_key, &party2_H0, &party2_key, &party2_key_agg.hash1_a2);

        // signature s:
        let (r_x, s) = party_one::Party1EphemeralKey::add_signature_parts(&s1, &s2, &party1_Rtag);

        // verify:
        assert!(party_one::Party1EphemeralKey::verify(&ec_context, &s, &r_x, &party1_key_agg.apk, &message, &is_musig).is_ok())

    }

    #[test]

    fn test_schnorr_one_party(){
        let is_musig = false;
        let ec_context = EC::new();
        let message: [u8; 4] = [79, 77, 69, 82];
        let party1_key = party_one::Party1KeyGen::key_gen(&ec_context);
        let party1_ephemeral_key = party_one::Party1EphemeralKey::create_from_private_key(&ec_context, &party1_key, &message);

        // compute c = H0(Rtag || apk || message)
        let party1_H0 = party_one::Party1EphemeralKey::hash_0(&party1_ephemeral_key.party1_ephemeral_public_key,
                                                              &party1_key.party1_public_key, &message, &is_musig);

        // compute partial signature s_i and send to the other party:
        let s1 = party_one::Party1EphemeralKey::sign1(&party1_ephemeral_key, &party1_H0, &party1_key, &BigInt::from(1));

        // signature s:
        let (R, s) = party_one::Party1EphemeralKey::add_signature_parts(&s1, &BigInt::from(0), &party1_ephemeral_key.party1_ephemeral_public_key);

        // verify:
        assert!(party_one::Party1EphemeralKey::verify(&ec_context, &s, &R, &party1_key.party1_public_key, &message, &is_musig).is_ok())

    }


    #[test]

    fn test_schnorr_bip_test_vector_2(){
        let ec_context = EC::new();
        let private_key_raw =  "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF";
        //let public_key_raw =  "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B";
        let message_raw =  "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89";

        let is_musig = false;
        let ec_context = EC::new();
        //println!("test {:?}",hex::decode(message_raw));
        let message = hex::decode(message_raw).unwrap();
       // println!("test2 {:?}",message);
        let party1_key = party_one::Party1KeyGen::key_gen_from_private_key(&ec_context, &BigInt::from_str_radix(&private_key_raw,16).unwrap());
        let party1_ephemeral_key = party_one::Party1EphemeralKey::create_from_private_key(&ec_context, &party1_key, &message);

        // compute c = H0(Rtag || apk || message)
        let party1_H0 = party_one::Party1EphemeralKey::hash_0(&party1_ephemeral_key.party1_ephemeral_public_key,
                                                              &party1_key.party1_public_key, &message, &is_musig);
        // compute partial signature s_i and send to the other party:
        let s1 = party_one::Party1EphemeralKey::sign1(&party1_ephemeral_key, &party1_H0, &party1_key, &BigInt::from(1));

        // signature s:
        let (R, s) = party_one::Party1EphemeralKey::add_signature_parts(&s1, &BigInt::from(0), &party1_ephemeral_key.party1_ephemeral_public_key);
        let test_vector_R = "2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d".to_string();
        let test_vector_s = "1e51a22ccec35599b8f266912281f8365ffc2d035a230434a1a64dc59f7013fd".to_string();
        let sig_R = R.to_str_radix(16);
        let sig_s = s.to_str_radix(16);
        assert_eq!(test_vector_R,sig_R);
        assert_eq!(test_vector_s,sig_s);
        // verify:
        assert!(party_one::Party1EphemeralKey::verify(&ec_context, &s, &R, &party1_key.party1_public_key, &message,&is_musig).is_ok())

    }

}
