package gov.niarl.his.privacyca;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;

import blaufish.test.tpm2.TestData;

class Tpm2UtilsTest {

	@Test
	void testMakeCredential() throws Exception {
		byte[] objectName = TestData.getAkRsaObjectName();
		RSAPublicKey publicKey = keyGen();
		Tpm2Credential out = Tpm2Utils.makeCredential(publicKey, Tpm2Algorithm.Symmetric.AES, 128,
				Tpm2Algorithm.Hash.SHA256, "12345678\n".getBytes(), objectName);
		assertNotNull(out.getCredential());
		assertNotNull(out.getSecret());
//		System.out.println(Hexdump.hexdump("secret", out.getSecret()));
//		System.out.println(Hexdump.hexdump("credential", out.getCredential()));
	}



	private RSAPublicKey keyGen() throws NoSuchAlgorithmException {
		RSAPublicKey publicKey;
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		publicKey = (RSAPublicKey) keyGen.genKeyPair().getPublic();
		return publicKey;
	}
}
