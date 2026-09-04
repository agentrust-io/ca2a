# Bare RSA signature prefix-collision vector

This frozen synthetic vector exercises cA2A's legacy bare-signature API. The
256-byte RSASSA/SHA-256 signature is valid for `attest.hex` under the leaf in
`ak-chain.pem`, but begins with `00 16`. Interpreting those already-bare bytes
as a marshalled `TPMT_SIGNATURE` therefore mistakes `0x0016` for
`TPM_ALG_RSAPSS` and fails while trying to parse a structure that is not there.

The vector was generated offline by varying the quote's qualifying data and
signing each otherwise fixed synthetic quote until counter `88540` produced the
required prefix. No private key is included. SHA-256:

- `attest.hex` decoded bytes:
  `55f4158f2ee2d5bbb5f3e3f2e9e55b9f86ba83337c1a666ce16f227bd4cea82d`
- `signature.hex` decoded bytes:
  `983fe06c34b2d9eabc98cded3aeac2f4ab9a6774c93d14f0ec11ea6bcf2521e2`

This is a compatibility/availability regression vector. It does not
demonstrate forged-evidence acceptance.
