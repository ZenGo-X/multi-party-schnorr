[![Build Status](https://travis-ci.com/ZenGo-X/multi-party-schnorr.svg?branch=master)](https://travis-ci.com/KZen-networks/multi-party-schnorr)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Multi Party Schnorr Signatures
=====================================
This library contains several Rust implementations of multi-signature Schnorr schemes. 
Generally speaking, these schemes can be classified into: 
1. {n,n}-multi-signature scheme (musig). These schemes require that all parties engage in cooperation to issue the signature. 
2. {t,n}-threshold-signature schemes (TSS). These schemes require that any subset of at least t+1 parties engage in cooperation to issue a valid signature.

##Different protocol implementation
This repo implement different Schnorr multi-signature schemes. There is tradoffs between these schemes with respect to type, performance, communications rounds and security assumptions. 
We use abbreviations DLP, ROM, ASM for respectively, discrete log problem, random oracle model, algebraic group model. 

| protocol | Type | Rounds | Assumptions | comments | 
| ----------| --------|-------|----------| --- |
| Maxwell, et al. [1] |  {n,n} | 3 | DLP, ROM | flawed security proof 
| Boneh, et al. [2] (section 5)|  {n,n} | 3 | DLP, ROM | fixes the security proof of [1]  
| Nick, et al. [3] |  {n,n} | 2 | DLP, ROM, AGM  | improvement on [2]  
| Micali, et al. [4] |  {n,n} | 3 | DLP, ROM | 
| Stinson-Strobl [5] |  {t,n} | 3 | DLP, ROM |  See (*)


(*)  For more efficient implementation we used the DKG from [Fast Multiparty Threshold ECDSA with Fast Trustless Setup](http://stevengoldfeder.com/papers/GG18.pdf). The cost is robustness: if there is a malicious party out of the n parties in DKG the protocol stops and if there is a malicious party out of the t parties used for signing the signature protocol will stop



**Disclaimers**: 

(1) This code should not be used for production at the moment.

(2) This code is not secure against side-channel attacks

(3) The code do not contain a network layer (if you are interested, check [white-city](https://github.com/KZen-networks/white-city) for ongoing effort, contribtutions are welcome)

<!---
Get Started
=====================================
[schnorr_bip_test_vector_2](https://github.com/KZen-networks/multi-party-schnorr/blob/master/src/protocols/aggsig/test.rs#L137)

[schnorr_two_party_signing](https://github.com/KZen-networks/multi-party-schnorr/blob/master/src/protocols/aggsig/test.rs#L26)

[threshold 3 out of 5 with 4 parties in signing](https://github.com/KZen-networks/multi-party-schnorr/blob/master/src/protocols/thresholdsig/test.rs#L61)
--->

Development Process
-------------------
This contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Contact
-------------------
Feel free to [reach out](mailto:github@kzencorp.com) or join the ZenGo X [Telegram](https://t.me/zengo_x) for discussions on code and research.

License
-------
The library is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.

## References

[1] <https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/simple_schnorr_multi_signatures_with_applications_to_bitcoin.pdf>

[2] <https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/compact_multi_signatures_for_smaller_blockchains.pdf>

[3] <https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/musig2_simple_two_round_schnorr_multi_signatures.pdf>

[4] <https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/accountable_subgroups_multisignatures.pdf>

[5] <https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/provably_secure_distributed_schnorr_signatures_and_a_threshold_scheme.pdf>