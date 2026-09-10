# CFRG hash-to-curve test vectors

These are selected fields from the SHA-256 `expand_message_xmd` and P-256
random-oracle vector files in the CFRG hash-to-curve proof of concept at commit
`664b13592116cecc9e52fb192dcde0ade36f904e`:

- https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/tree/664b13592116cecc9e52fb192dcde0ade36f904e/poc/vectors

The short-DST file covers one- and four-block expansion. The long-DST file
covers the RFC 9380 oversized-DST hashing rule for the same output lengths.
The P-256 file covers every published message and final `HashToGroup` point;
intermediate field elements and mapping points were omitted.
