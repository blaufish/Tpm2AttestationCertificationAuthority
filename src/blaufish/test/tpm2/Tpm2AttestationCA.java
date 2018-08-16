package blaufish.test.tpm2;

import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Tpm2AttestationCA {
	private X509Certificate manufacturerCertificate;

	private Tpm2AttestationCA(X509Certificate manufacturerCertificate) {
		this.manufacturerCertificate = manufacturerCertificate;
	};

	public void verifyEKCert(X509Certificate ekcert) throws InvalidKeyException, CertificateException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		ekcert.verify(manufacturerCertificate.getPublicKey());
	}

	public static Tpm2AttestationCA build(X509Certificate manufacturerCertificate) throws CertificateException, FileNotFoundException {
		Tpm2AttestationCA ca = new Tpm2AttestationCA(manufacturerCertificate);
		return ca;
	}
}
