#!/bin/sh
set -e
rm temp.* || echo "Ignore errors"

sudo chgrp tss .
# Clear TPM handles
sudo -u tss tpm2_evictcontrol -Q -A o -H 0x81010007 --tcti device:/dev/tpmrm0 || echo "Ingore errors"
sudo -u tss tpm2_evictcontrol -Q -A o -H 0x81010008 --tcti device:/dev/tpmrm0 || echo "Ignore errors"

# Get EKPubCert
sudo -u tss tpm2_nvread --tcti device:/dev/tpmrm0 --index 0x1c00002 -a 0x40000001 -o 0 > temp.nvread.1c0002.cert
# Get EKpub, AKpub
sudo -u tss tpm2_getpubek --tcti device:/dev/tpmrm0 -H 0x81010007 -g 0x0001 -f temp.ek_rsa.pub
sudo -u tss tpm2_getpubak --tcti device:/dev/tpmrm0 -E 0x81010007 -k 0x81010008 -g 0x0001 -D 0x000b -s 0x0016 -f temp.ak_rsa.pub -n temp.ak_rsa.name

# Proof of ownership challenge
java -cp ../bin:../libs/bcpkix-jdk15on-160.jar:../libs/bcprov-jdk15on-160.jar \
blaufish.test.tpm2.Tpm2AttestationCACli \
  --in-akname=temp.ak_rsa.name \
  --in-akpub=temp.ak_rsa.pub \
  --in-ekcert=temp.nvread.1c0002.cert \
  --in-tpm-manufacturer-cert=../test/OptigaRsaMfrCA022.crt \
  --out-cacert=temp.ca.cert \
  --out-tpm-akcert-encrypted=temp.akcert.encrypted \
  --out-tpm-credential=temp.credential

# Decrypt secret, completing proof of ownership
sudo -u tss tpm2_activatecredential --tcti device:/dev/tpmrm0 -H 0x81010008 -k 0x81010007 -f temp.credential -o temp.credential.decrypted
sudo -u tss tpm2_quote --tcti device:/dev/tpmrm0 -k 0x81010008 -l 16,17,18 -q 375D6C8AE683285D09F04264120886CD0C11C156311530E24A4D20F576EBA467 -m temp.quote_rsa.bin
