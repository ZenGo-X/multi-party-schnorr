#![allow(non_snake_case)]
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
#[allow(unused_doc_comments)]
/*
    Multisig Schnorr

    Copyright 2020 by Kohei Taniguchi

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multisig-schnorr/blob/master/LICENSE>
*/
use curv::{FE, GE};

/// Compute e = h(V || Y || message)
pub fn compute_e(v: &GE, y: &GE, message: &[u8]) -> FE {
    let v = v.get_element().serialize();
    let y = y.get_element().serialize();

    let mut vec: Vec<u8> = Vec::with_capacity(v.len() + y.len() + message.len());
    vec.extend(&v[..]);
    vec.extend(&y[..]);
    vec.extend(message);

    let e_bn = HSha256::create_hash_from_slice(&vec[..]);
    ECScalar::from(&e_bn)
}

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{BigInt, FE, GE};
    use protocols::thresholdsig::util::compute_e;

    #[test]
    fn test_compute_e() {
        let v_x_bn = BigInt::from_str_radix(
            "06705d6b7fd5a7a34ea47b6a8d0ce8372a83d2129a65458e2bef6f45892e7d5d",
            16,
        )
        .unwrap();
        let v_y_bn = BigInt::from_str_radix(
            "c6441397d43ff1e0bd9d7da39caf55dffbaa246fb70b1d08d2aa85903e7ec3e0",
            16,
        )
        .unwrap();
        let v: GE = ECPoint::from_coor(&v_x_bn, &v_y_bn);

        let y_x_bn = BigInt::from_str_radix(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            16,
        )
        .unwrap();
        let y_y_bn = BigInt::from_str_radix(
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            16,
        )
        .unwrap();
        let y: GE = ECPoint::from_coor(&y_x_bn, &y_y_bn);

        // It should be equal to expected when the message started with "00" byte.
        let message =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();

        let expected_bn = BigInt::from_str_radix(
            "85e8da2401b58b960965aab0df09554fde8d1e41b67b9cebac8d8421d6919c2a",
            16,
        )
        .unwrap();
        let expected: FE = ECScalar::from(&expected_bn);

        assert_eq!(expected, compute_e(&v, &y, &message[..]));
    }
}
