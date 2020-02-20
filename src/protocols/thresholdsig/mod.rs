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
/// variant (2)
pub mod bitcoin_schnorr;
mod util;
mod test_bitcoin;
mod test_zilliqa;
/// Schnorr signature variants:
/// Elliptic Curve Schnorr signatures for message m and public key P generally involve
/// a point R, integers e and s picked by the signer, and generator G which satisfy e = H(R || m)
/// and sG = R + eP. Two formulations exist, depending on whether the signer reveals e or R:
/// (1) Signatures are (e,s) that satisfy e = H(sG - eP || m).
/// This avoids minor complexity introduced by the encoding of the point R in the signature
/// (2) Signatures are (R,s) that satisfy sG = R + H(R || m)P. This supports batch verification,
/// as there are no elliptic curve operations inside the hashes.

/// variant (1)
pub mod zilliqa_schnorr;