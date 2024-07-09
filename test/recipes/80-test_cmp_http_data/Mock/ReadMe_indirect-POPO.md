#  Indirect POPO

For testing Indirect POPO, checkout below branch from siemens/openssl
```
https://github.com/siemens/openssl/tree/CMP_KEM_cert_indirect_popo

````

#  Prerequisite

oqs provider is required to use PQ algorithms.

To execute CMP client for KEM certificates- 
```
$ cd test/recipes/80-test_cmp_http_data/Mock
$ openssl cmp -server 127.0.0.1:1701 -config test.cnf -section "Mock commands" -no_proxy 127.0.0.1 -cmd cr -cert signer.crt -key signer.key -certout out.test.pem -popo 2 -newkey kyber1024.priv -srvcert server.crt  -out_trusted root.crt -provider oqsprovider -provider default
````

Following configuration need to be adapted:

  - "-cert signer.crt" & "-key signer.key" is CMP protection credentials.
  - "-newkey kyber1024.priv" is the key of new certificates.
  - "-srvcert server.crt" Server cert to pin and trust directly when verifying signed CMP responses.
  - "out_trusted root.crt" is TA for newly enrolled certificates.

 