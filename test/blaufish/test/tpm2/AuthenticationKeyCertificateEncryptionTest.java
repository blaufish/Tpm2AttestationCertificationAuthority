package blaufish.test.tpm2;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.file.Files;


import org.junit.jupiter.api.Test;

class AuthenticationKeyCertificateEncryptionTest {

	@Test
	void testSelf() throws Exception {
		byte[] key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
		byte[] original = { 1, 3, 3, 7 };
		byte[] encrypted = AuthenticationKeyCertificateEncryption.encrypt(key, original);
		byte[] decrypted = AuthenticationKeyCertificateEncryption.decrypt(key, encrypted);
		assertArrayEquals(original, decrypted);
	}
	
	@Test
	void testFiles() throws Exception {
		byte[] akCertEncrypted = Files.readAllBytes(new File("test/akcert.encrypted").toPath());
		byte[] credentialDecrypted = Files.readAllBytes(new File("test/credential.decrypted").toPath());
		byte[] decrypted = AuthenticationKeyCertificateEncryption.decrypt(credentialDecrypted, akCertEncrypted);
		assertNotNull(decrypted);
	}

}
