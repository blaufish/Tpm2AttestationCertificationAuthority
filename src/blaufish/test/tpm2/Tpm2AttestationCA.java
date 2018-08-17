package blaufish.test.tpm2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import gov.niarl.his.privacyca.Tpm2Algorithm;
import gov.niarl.his.privacyca.Tpm2Credential;
import gov.niarl.his.privacyca.Tpm2Utils;

public class Tpm2AttestationCA {
	X509Certificate manufacturerCertificate;
	SecureRandom sr;

	public static Tpm2AttestationCA build(X509Certificate manufacturerCertificate)
			throws CertificateException, FileNotFoundException {
		Tpm2AttestationCA ca = new Tpm2AttestationCA(manufacturerCertificate);
		return ca;
	}

	private Tpm2AttestationCA(X509Certificate manufacturerCertificate) {
		this.manufacturerCertificate = manufacturerCertificate;
		this.sr = new SecureRandom();
	};

	void verifyEKCert(X509Certificate ekcert) throws InvalidKeyException, CertificateException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		ekcert.verify(manufacturerCertificate.getPublicKey());
	}

	Tpm2Credential makeCredential(X509Certificate ekcert, byte[] credential, byte[] objectName)
			throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, ShortBufferException, IOException {
		verifyEKCert(ekcert);
		Tpm2Credential out = Tpm2Utils.makeCredential(ekcert.getPublicKey(), Tpm2Algorithm.Symmetric.AES, 128,
				Tpm2Algorithm.Hash.SHA256, credential, objectName);
		return out;
	}

	byte[] convertToTpm2Tools(Tpm2Credential cred) {
		int MAGIC = 0xBADCC0DE;
		int len_encrypted_credential = tpmlength(cred.getCredential());
		int len_encrypted_secret = tpmlength(cred.getSecret());
		ByteBuffer b = ByteBuffer.allocateDirect(12 + len_encrypted_credential + len_encrypted_secret);
		b.order(ByteOrder.BIG_ENDIAN);
		b.putInt(MAGIC);
		b.putInt(1);
		b.putShort((short) len_encrypted_credential);
		b.put(cred.getCredential(), 2, len_encrypted_credential);
		b.putShort((short) len_encrypted_secret);
		b.put(cred.getSecret(), 2, len_encrypted_secret);
		b.rewind();
		byte[] bytes = new byte[b.remaining()];
		b.get(bytes);
		return bytes;
	}

	private int tpmlength(byte[] blob) {
		return (blob[0] & 0xFF) | ((blob[1] & 0xFF) << 8);
	}
}
