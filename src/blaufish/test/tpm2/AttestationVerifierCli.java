package blaufish.test.tpm2;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class AttestationVerifierCli {
	static final int TPM_ALG_RSAPSS = 0x0016;
	static final int TPM_ALG_SHA256 = 0x000B;
	static final int RSA2048_SIG_LEN = 256;

	static boolean verify(X509Certificate caCert, X509Certificate akCert, byte[] attest, byte[] signature)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			InvalidAlgorithmParameterException, SignatureException, CertificateException {
		akCert.verify(caCert.getPublicKey());
		return tpm2_rsa_pss_verify(akCert, attest, signature);
	}

	static boolean tpm2_rsa_pss_verify(X509Certificate akCert, byte[] rsa_bin, byte[] rsa_sig)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
			InvalidKeyException, SignatureException {
		if (rsa_sig.length < 6)
			return false;
		if (TPM_ALG_RSAPSS != readBigEndianUnsigned16(rsa_sig, 0))
			return false;
		if (TPM_ALG_SHA256 != readBigEndianUnsigned16(rsa_sig, 2))
			return false;
		if (RSA2048_SIG_LEN != readBigEndianUnsigned16(rsa_sig, 4))
			return false;
		Signature signature = Signature.getInstance("SHA256withRSAandMGF1", "BC");
		signature.setParameter(
				new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 256 - 32 - 2, 1));
		signature.initVerify(akCert.getPublicKey());
		signature.update(rsa_bin);
		boolean signatureValidationResult = signature.verify(rsa_sig, 6, RSA2048_SIG_LEN);
		return signatureValidationResult;
	}

	static int readBigEndianUnsigned16(byte[] b, int offset) {
		return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
	}

	public static void main(String[] args) {
		// TODO Not Implemented Yet
		System.exit(1);
	}
}
