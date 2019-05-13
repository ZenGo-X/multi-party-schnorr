[![Build Status](https://travis-ci.com/KZen-networks/multi-party-schnorr.svg?branch=master)](https://travis-ci.com/KZen-networks/multi-party-schnorr)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Multi Party Schnorr Signatures
=====================================
* Aggragated Signatures:  {n,n} scheme based on [simple_schnorr_multi_signatures_with_applications_to_bitcoin](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/simple_schnorr_multi_signatures_with_applications_to_bitcoin.pdf) and the scheme for discrete-logs (section 5) from [compact_multi_signatures_for_smaller_blockchains](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/compact_multi_signatures_for_smaller_blockchains.pdf) 
* Multi-signature scheme based on Micali-Ohta-Reyzin: [Accountable-Subgroup Multisignatures](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/accountable_subgroups_multisignatures.pdf). This code is being used currently for [2p-Schnorr key management](https://github.com/KZen-networks/kms-secp256k1 ).
* Threshold Schnorr scheme based on [provably secure distributed schnorr signatures and a {t,n} threshold scheme](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/provably_secure_distributed_schnorr_signatures_and_a_threshold_scheme.pdf). For more efficient implementation we used the DKG from [Fast Multiparty Threshold ECDSA with Fast Trustless Setup](http://stevengoldfeder.com/papers/GG18.pdf). The cost is robustness: if there is a malicious party out of the n parties in DKG the protocol stops and if there is a malicious party out of the t parties used for signing the signature protocol will stop.
* The implementations aim to be [_bip-schnorr_](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki) compliant.

* [Paper List](https://github.com/KZen-networks/multi-party-schnorr/tree/master/papers), [Wiki](https://github.com/KZen-networks/multisig-schnorr/wiki).

**Disclaimers**: 

(1) This code should not be used for production at the moment.

(2) This code is not secure against side-channel attacks

(3) The code do not contain a network layer (if you are interested, check [white-city](https://github.com/KZen-networks/white-city) for ongoing effort, contribtutions are welcome)


Get Started
=====================================

[schnorr_bip_test_vector_2](https://github.com/KZen-networks/multi-party-schnorr/blob/master/src/protocols/aggsig/test.rs#L137)

[schnorr_two_party_signing](https://github.com/KZen-networks/multi-party-schnorr/blob/master/src/protocols/aggsig/test.rs#L26)

[threshold 3 out of 5 with 4 parties in signing](https://github.com/KZen-networks/multi-party-schnorr/blob/master/src/protocols/thresholdsig/test.rs#L61)

Development Process
-------------------
This contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Contact
-------------------
Feel free to [reach out](mailto:github@kzencorp.com) or join the KZen Research [Telegram]( https://t.me/kzen_research) for discussions on code and research.

License
-------
The library is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.
