#!/bin/sh

java -cp bin:libs/bcpkix-jdk15on-160.jar:libs/bcprov-jdk15on-160.jar \
blaufish.test.tpm2.Tpm2AttestationCACli \
  --in-akname=test/ak_rsa.name \
  --in-akpub=test/ak_rsa.pub \
  --in-ekcert=test/nvread.1c0002.cert \
  --in-tpm-manufacturer-cert=test/OptigaRsaMfrCA022.crt \
  --out-cacert=test/temp.ca.cert \
  --out-tpm-akcert-encrypted=test/temp.akcert.encrypted \
  --out-tpm-credential=test/temp.credential