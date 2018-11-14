[![Build Status](https://travis-ci.com/KZen-networks/multisig-schnorr.svg?branch=master)](https://travis-ci.com/KZen-networks/multisig-schnorr)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Threshold Schnorr signatures
=====================================
Currently supporting two protocols: 
* Aggragated Signatures:  {n,n} scheme based on https://eprint.iacr.org/2018/068.pdf and the scheme for discrete-logs (section 5) from https://eprint.iacr.org/2018/483.pdf  
* Multi-signature scheme based on  Micali-Ohta-Reyzin: Accountable-Subgroup Multisignatures: https://pdfs.semanticscholar.org/6bf4/f9450e7a8e31c106a8670b961de4735589cf.pdf. This code is being used currently in: https://github.com/KZen-networks/kms-secp256k1 for 2p-schnorr for crypto-wallet.

The implementations are _bip-schnorr_ compatible (https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki)

Disclaimer: (1) This code should not be used for production at the moment. (2) This code is not secure against side-channel attacks

A wiki is available here: https://github.com/KZen-networks/multisig-schnorr/wiki.

License
-------
Multisig Schnorr is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.

Development Process
-------------------
The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Contact
-------------------
For any questions, feel free to [email us](mailto:github@kzencorp.com).
