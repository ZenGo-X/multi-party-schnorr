[![Build Status](https://travis-ci.com/KZen-networks/multi-party-schnorr.svg?branch=master)](https://travis-ci.com/KZen-networks/multi-party-schnorr)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Threshold Schnorr signatures
=====================================
Currently supporting two protocols: 
* Aggragated Signatures:  {n,n} scheme based on [simple_schnorr_multi_signatures_with_applications_to_bitcoin](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/simple_schnorr_multi_signatures_with_applications_to_bitcoin.pdf) and the scheme for discrete-logs (section 5) from [compact_multi_signatures_for_smaller_blockchains](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/compact_multi_signatures_for_smaller_blockchains.pdf) 
* Multi-signature scheme based on  Micali-Ohta-Reyzin: [Accountable-Subgroup Multisignatures](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/accountable_subgroups_multisignatures.pdf). This code is being used currently  for [2p-Schnorr key management](https://github.com/KZen-networks/kms-secp256k1 ).

The implementations aim to be [_bip-schnorr_](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki) compatible.

Disclaimer: (1) This code should not be used for production at the moment. (2) This code is not secure against side-channel attacks

A wiki is available here: https://github.com/KZen-networks/multisig-schnorr/wiki.


Development Process
-------------------
This contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Contact
-------------------
For any questions, feel free to [email us](mailto:github@kzencorp.com).

License
-------
The library is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.
