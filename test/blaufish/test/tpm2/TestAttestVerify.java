package blaufish.test.tpm2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

class TestAttestVerify {
	final int TPM_ALG_RSAPSS = 0x0016;
	final int TPM_ALG_SHA256 = 0x000B;

	@Test
	void test() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		X509Certificate caCert = readCert("test/cacert.der");
		X509Certificate akCert = readCert("test/akcert.der");
		byte[] rsa_bin = read("test/quote_rsa.bin");
		byte[] rsa_sig = read("test/quote_rsa.sig");
		assertEquals(TPM_ALG_RSAPSS, readBigEndianUnsigned16(rsa_sig, 0));
		assertEquals(TPM_ALG_SHA256, readBigEndianUnsigned16(rsa_sig, 2));
		assertEquals(256, readBigEndianUnsigned16(rsa_sig, 4));
		boolean result = AttestationVerifierCli.verify(caCert, akCert, rsa_bin, rsa_sig);
		assertTrue(result);
	}

	private static int readBigEndianUnsigned16(byte[] b, int offset) {
		return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
	}

	private byte[] read(String pathname) throws IOException {
		return Files.readAllBytes(new File(pathname).toPath());
	}

	private X509Certificate readCert(String certificateFile) throws CertificateException, FileNotFoundException {
		return (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new FileInputStream(certificateFile));
	}
}
