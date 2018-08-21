# Tpm2AttestationCertificationAuthority
Test project for Attestation CA, previously referred to as Privacy CA 

## Dependencies
* Depends on gov.niarl.his.privacyca from opencit. 
* Read/write [TPM2Tools 3.1.0](https://github.com/tpm2-software/tpm2-tools/tree/3.1.0) compatible files.

## Command line
The CA can be used from command line:

```
java -cp bin:libs/bcpkix-jdk15on-160.jar:libs/bcprov-jdk15on-160.jar \
blaufish.test.tpm2.Tpm2AttestationCACli \
  --in-akname=test/ak_rsa.name \
  --in-akpub=test/ak_rsa.pub \
  --in-ekcert=test/nvread.1c0002.cert \
  --in-tpm-manufacturer-cert=test/OptigaRsaMfrCA022.crt \
  --out-cacert=test/temp.ca.cert \
  --out-tpm-akcert-encrypted=test/temp.akcert.encrypted \
  --out-tpm-credential=test/temp.credential
```

The CA will generate:
* `test/temp.crediantial`, a file that can be only decrypted with the *TPM Endorsement Key* using the tpm2_activatecredential (Proof of Ownership). In this demo, the credentials contained within is an AES-key.
* `test/temp.akcert.encrypted`, a file that can only be decrypted by the AES-key hidden inside the credentials.
* `temp.ca.cert`, the root CA certificate (just a dummy for now).

Input files are generated as follows:

```
tpm2_evictcontrol -Q -A o -H 0x81010007 --tcti device:/dev/tpmrm0
tpm2_evictcontrol -Q -A o -H 0x81010008 --tcti device:/dev/tpmrm0
tpm2_getpubek --tcti device:/dev/tpmrm0 -H 0x81010007 -g 0x0001 -f ek_rsa.pub
tpm2_getpubak --tcti device:/dev/tpmrm0 -E 0x81010007 -k 0x81010008 -g 0x0001 -D 0x000b -s 0x0016 -f ak_rsa.pub -n ak_rsa.name
loaded-key:
  handle: 80ffffff
  name: 000bd3dc102187be259f12f361bc0c231f5a9788a48a6a832d11d99dc8ce1b5eafca
```

## Bugs and future improvements
* TPMT_PUBLIC parsing of TPM Authentication Key is, eh, very crude and not portable-
* gov.niarl.his.privacyca classes only support RSA, not ECC.
