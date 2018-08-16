package blaufish.test.tpm2;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Tpm2AttestationCATest {
	private static final String MANUFACTURER_ECC_CERT = "test/OptigaEccMfrCA022.crt";
	private static final String ENDORSEMENT_KEY_ECC_CERT = "test/nvread.1c000a.cert";
	Tpm2AttestationCA eccCa;
	CertificateFactory certificateFactory;

	@BeforeEach
	void before() throws Exception {
		certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate manufacturerCertificate = loadCertificate(MANUFACTURER_ECC_CERT);
		eccCa = Tpm2AttestationCA.build(manufacturerCertificate);
	}

	private X509Certificate loadCertificate(String certificateFile) throws CertificateException, FileNotFoundException {
		return (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(certificateFile));
	}

	@AfterEach
	void after() {
		eccCa = null;
		certificateFactory = null;
	}

	@Test
	void testBuild() {
		assertNotNull(eccCa);
	}

	@Test
	void testEKVerify() throws Exception {
		eccCa.verifyEKCert(loadCertificate(ENDORSEMENT_KEY_ECC_CERT));
	}
}
