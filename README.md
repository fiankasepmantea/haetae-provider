This implementation uses raw binary format for keys and signatures.
No ASN.1 or PEM/DER encoding is implemented.

#### Public Key
- Length: CRYPTO_PUBLICKEYBYTES bytes
- Format: [b || rhoprime]
  - `b`: compressed polyveck (polynomial vector)
  - `rhoprime`: seed used to expand matrix A (32 bytes)

#### Secret Key
- Length: CRYPTO_SECRETKEYBYTES bytes
- Format: [s1 || s2 || key || pk]
  - `s1`, `s2`: secret vectors (polyvecm, polyveck)
  - `key`: signing seed (usually 32 bytes)
  - `pk`: full public key (same format as above)

#### Signature
- Length: CRYPTO_BYTES bytes
- Format: [c || lb_z1 || hb_z1 || h]
  - `c`: challenge polynomial
  - `lb_z1`: low bits of z1
  - `hb_z1`: high bits of z1
  - `h`: high-bit hint vector
