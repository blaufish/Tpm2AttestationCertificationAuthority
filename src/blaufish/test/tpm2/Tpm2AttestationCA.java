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
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.operator.OperatorCreationException;

import gov.niarl.his.privacyca.Tpm2Algorithm;
import gov.niarl.his.privacyca.Tpm2Credential;
import gov.niarl.his.privacyca.Tpm2Utils;

public class Tpm2AttestationCA {
	private X509Certificate authorityCertificate;
	private X509Certificate manufacturerCertificate;
	private CertTool certificateTool;
	public static Tpm2AttestationCA build(X509Certificate manufacturerCertificate)
			throws CertificateException, FileNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {

        CertTool ct = CertTool.build();

		Tpm2AttestationCA ca = new Tpm2AttestationCA(manufacturerCertificate, ct.generateCert(25), ct);
		return ca;
	}
	
	private Tpm2AttestationCA(X509Certificate manufacturerCertificate, X509Certificate authorityCertificate, CertTool ct) {
		this.manufacturerCertificate = manufacturerCertificate;
		this.authorityCertificate = authorityCertificate;
		this.certificateTool = ct;
	};

	public X509Certificate getAuthorityCertificate() {
		return authorityCertificate;
	}

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

	private static int tpmlength(byte[] blob) {
		return (blob[0] & 0xFF) | ((blob[1] & 0xFF) << 8);
	}
	
	TupleForTpm generateAkCert(X509Certificate ekcert, byte[] ak_pub, byte[] ak_objectname) throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidAlgorithmParameterException, ShortBufferException, IOException {
		byte[] aes_key = new byte[16];
		byte[] unencrypted_cert = certificateTool.generateLeafCert(1, "CN=test", encode_tpmt_public_to_asn1(ak_pub)).getEncoded();
		SecureRandom random = new SecureRandom();
		random.nextBytes(aes_key);
		SecretKeySpec key = new SecretKeySpec(aes_key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encrypted_cert = cipher.doFinal(unencrypted_cert);
		//encrypt to the proof of possession
		Tpm2Credential cred = makeCredential(ekcert, aes_key, ak_objectname);
		byte[] formatted_cred = convertToTpm2Tools(cred);
		return new TupleForTpm(formatted_cred, encrypted_cert);		
	}
	private byte[] encode_tpmt_public_to_asn1(byte[] ak_pub) {
		/* https://dguerriblog.wordpress.com/2016/03/03/tpm2-0-and-openssl-on-linux-2/ */
		byte[] asn1header = {0x30, (byte)0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, (byte)0x86,
				0x48, (byte)0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, (byte)0x82, 
				0x01, 0x0f, 0x00, 0x30, (byte) 0x82, 0x01, 0x0a, 0x02, (byte) 0x82, 0x01, 0x01, 0x00};
		byte[] asn1midHeaderAndExponent65537 = {0x02, 03, 0x01, 0x00, 0x01};
		int asn1bloblength = asn1header.length + 256 + asn1midHeaderAndExponent65537.length;
		byte[] blob = new byte[asn1bloblength];
		ByteBuffer buf = ByteBuffer.wrap(blob);
		buf.put(asn1header);
		//FIXME 0x1A is a tpm or tool-specific hack. the blog got 102 instead due to different TPMT_PUBLIC structures!!! 
		buf.put(ak_pub, 0x1A, 256);
		buf.put(asn1midHeaderAndExponent65537);
		return blob;
	}

	static class TupleForTpm {
		public TupleForTpm(byte[] tpmCredential, byte[] encryptedAkCertificate) {
			super();
			this.tpmCredential = tpmCredential;
			this.encryptedAkCertificate = encryptedAkCertificate;
		}
		final private byte[] tpmCredential;
		final private byte[] encryptedAkCertificate;
		public byte[] getTpmCredential() {
			return tpmCredential;
		}
		public byte[] getEncryptedAkCertificate() {
			return encryptedAkCertificate;
		}
	}
}