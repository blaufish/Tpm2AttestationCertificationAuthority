package blaufish.test.tpm2;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.junit.jupiter.api.Test;

class TestAttestVerify {
	final int TPM_ALG_RSAPSS = 0x0016;
	final int TPM_ALG_SHA256 = 0x000B;

	@Test
	void test() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		X509Certificate akCert = readCert("integration-test/temp.akcert.decrypted");
		byte[] rsa_bin = read("integration-test/temp.quote_rsa.bin");
		byte[] rsa_sig = read("integration-test/temp.quote_rsa.sig");
		assertEquals(TPM_ALG_RSAPSS, readBigEndianUnsigned16(rsa_sig, 0));
		assertEquals(TPM_ALG_SHA256, readBigEndianUnsigned16(rsa_sig, 2));
		assertEquals(256, readBigEndianUnsigned16(rsa_sig, 4));
		Signature signature = Signature.getInstance("SHA256withRSAandMGF1", "BC");
		signature.setParameter(
				new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 256 - 32 - 2, 1));
		signature.initVerify(akCert.getPublicKey());
		signature.update(rsa_bin);
		boolean r = signature.verify(rsa_sig, 6, 256);
		assertTrue(r);
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
