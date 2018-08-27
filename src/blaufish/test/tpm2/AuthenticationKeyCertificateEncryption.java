package blaufish.test.tpm2;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class AuthenticationKeyCertificateEncryption {
	private AuthenticationKeyCertificateEncryption() {
	}

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	static byte[] decrypt(byte[] aes_key, byte[] encrypted_cert)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] nonce = new byte[7]; // Hard coded 00... because key only used once
		SecretKeySpec key = new SecretKeySpec(aes_key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
		byte[] unencrypted_cert = cipher.doFinal(encrypted_cert);
		return unencrypted_cert;
	}

	static byte[] encrypt(byte[] aes_key, byte[] unencrypted_cert)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		byte[] nonce = new byte[7]; // Hard coded 00... because key only used once
		SecretKeySpec key = new SecretKeySpec(aes_key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
		byte[] encrypted_cert = cipher.doFinal(unencrypted_cert);
		return encrypted_cert;
	}
}
