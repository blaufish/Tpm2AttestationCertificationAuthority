package blaufish.test.tpm2;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class Tpm2AttestationCATest {

	CertificateFactory certificateFactory;
	Tpm2AttestationCA ca;

	@BeforeEach
	void before() throws Exception {
		certificateFactory = CertificateFactory.getInstance("X.509");
		ca = null;
	}

	@AfterEach
	void after() {
		certificateFactory = null;
		ca = null;
	}

	private X509Certificate loadCertificate(String certificateFile) throws CertificateException, FileNotFoundException {
		return (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(certificateFile));
	}

	@Nested
	class ecc {
		private static final String MANUFACTURER_ECC_CERT = "test/OptigaEccMfrCA022.crt";
		private static final String ENDORSEMENT_KEY_ECC_CERT = "test/nvread.1c000a.cert";

		@BeforeEach
		void before() throws Exception {
			X509Certificate manufacturerEccCertificate = loadCertificate(MANUFACTURER_ECC_CERT);
			ca = Tpm2AttestationCA.build(manufacturerEccCertificate);
		}

		@Test()
		void testEKVerifyEcc() throws Exception {
			ca.verifyEKCert(loadCertificate(ENDORSEMENT_KEY_ECC_CERT));
		}
	}

	@Nested
	class rsa {
		private static final String MANUFACTURER_RSA_CERT = "test/OptigaRsaMfrCA022.crt";
		private static final String ENDORSEMENT_KEY_RSA_CERT = "test/nvread.1c0002.cert";

		@BeforeEach
		void before() throws Exception {
			X509Certificate manufacturerRsaCertificate = loadCertificate(MANUFACTURER_RSA_CERT);
			ca = Tpm2AttestationCA.build(manufacturerRsaCertificate);
		}

		@Test
		void testEKVerifyRsa() throws Exception {
			ca.verifyEKCert(loadCertificate(ENDORSEMENT_KEY_RSA_CERT));
		}
	}
}
