# Curve-ZKP

Curve-ZKP is a library focusing on Zero-Knowledge-Proofs using elliptic curves.

The following are provided from this library:

- Short group signatures [BBS+2016](https://eprint.iacr.org/2016/663) and Short Threshold Dynamic Group Signatures [CDLNT2020](https://eprint.iacr.org/2020/016)
- Accumulator [VB2020](https://eprint.iacr.org/2020/777)
- [Bulletproofs+](https://eprint.iacr.org/2020/735)

Short group signatures and accumulators are based on bilinear maps.
This library aims to provide easy to use interfaces while allowing
the consumer to pick a library without the need to change anything else.

The APIs are described [here](API.md)
