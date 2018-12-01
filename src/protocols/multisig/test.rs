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
    use curv::cryptographic_primitives::hashing::merkle_tree::MT256;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::FE;
    use protocols::multisig::{partial_sign, verify, EphKey, Keys, Signature};

    #[test]
    fn two_party_key_gen() {
        let message: [u8; 4] = [79, 77, 69, 82];
        // party1 key gen:
        let mut keys_1 = Keys::create();

        keys_1.I.update_key_pair(FE::zero());

        let broadcast1 = Keys::broadcast(keys_1.clone());
        // party2 key gen:
        let keys_2 = Keys::create();
        let broadcast2 = Keys::broadcast(keys_2.clone());
        let ix_vec = vec![broadcast1, broadcast2];
        let e = Keys::collect_and_compute_challenge(&ix_vec);

        let y1 = partial_sign(&keys_1, e.clone());
        let y2 = partial_sign(&keys_2, e.clone());
        let sig1 = Signature::set_signature(&keys_1.X.public_key, &y1);
        let sig2 = Signature::set_signature(&keys_2.X.public_key, &y2);
        // partial verify
        assert!(verify(&keys_1.I.public_key, &sig1, &e).is_ok());
        assert!(verify(&keys_2.I.public_key, &sig2, &e).is_ok());

        // merkle tree (in case needed)

        let ge_vec = vec![(keys_1.I.public_key).clone(), (keys_2.I.public_key).clone()];
        let mt256 = MT256::create_tree(&ge_vec);
        let proof1 = mt256.gen_proof_for_ge(&keys_1.I.public_key);
        let proof2 = mt256.gen_proof_for_ge(&keys_2.I.public_key);
        let root = mt256.get_root();

        //TODO: reduce number of clones.
        // signing
        let party1_com = EphKey::gen_commit();

        let party2_com = EphKey::gen_commit();

        let eph_pub_key_vec = vec![
            party1_com.eph_key_pair.public_key.clone(),
            party2_com.eph_key_pair.public_key.clone(),
        ];
        let pub_key_vec = vec![keys_1.I.public_key.clone(), keys_2.I.public_key.clone()];

        let (It, Xt, es) = EphKey::compute_joint_comm_e(pub_key_vec, eph_pub_key_vec, &message);

        let y1 = party1_com.partial_sign(&keys_1.I, es.clone());
        let y2 = party2_com.partial_sign(&keys_2.I, es.clone());
        let y = EphKey::add_signature_parts(vec![y1, y2]);
        let sig = Signature::set_signature(&Xt, &y);
        assert!(verify(&It, &sig, &es).is_ok());

        assert!(MT256::validate_proof(&proof1, root).is_ok());
        assert!(MT256::validate_proof(&proof2, root).is_ok());
    }

}
