#!/bin/sh
set -e

java -cp bin:libs/bcpkix-jdk15on-160.jar:libs/bcprov-jdk15on-160.jar \
blaufish.test.tpm2.AKCertDecryptCli \
  --in-credential=test/credential.decrypted \
  --in-encrypted-cert=test/akcert.encrypted \
  --out-cert=test/temp.akcert.decrypted2
