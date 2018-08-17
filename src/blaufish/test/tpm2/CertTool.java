package blaufish.test.tpm2;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertTool {
	private static final int DAY_IN_MILLISECONDS = 24 * 60 * 60 * 1000;
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	KeyPair pair;
	String distinguishedName;

	public CertTool(KeyPair pair, String distinguishedName) {
		this.pair = pair;
		this.distinguishedName = distinguishedName;
	}

	public static CertTool build() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(2048, new SecureRandom());
		KeyPair pair = kpGen.generateKeyPair();
		return new CertTool(pair, "CN=root,O=foo");

	}

	public X509Certificate generateCert(int validityDays)
			throws OperatorCreationException, CertificateException {
		ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate());
		Date startDate = new Date(System.currentTimeMillis() - DAY_IN_MILLISECONDS);
		Date endDate = new Date(System.currentTimeMillis() + validityDays * DAY_IN_MILLISECONDS);

		X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(new X500Name(distinguishedName), BigInteger.ONE, startDate,
				endDate, new X500Name(distinguishedName), SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));

		X509CertificateHolder certHolder = v1CertGen.build(sigGen);
		return new JcaX509CertificateConverter().getCertificate(certHolder);
	}
	public X509Certificate generateLeafCert(int validityDays, String dn, byte[] publicKey)
			throws OperatorCreationException, CertificateException {
		ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate());
		Date startDate = new Date(System.currentTimeMillis() - DAY_IN_MILLISECONDS);
		Date endDate = new Date(System.currentTimeMillis() + validityDays * DAY_IN_MILLISECONDS);

		X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(new X500Name(dn), BigInteger.ONE, startDate,
				endDate, new X500Name(dn), SubjectPublicKeyInfo.getInstance(publicKey));

		X509CertificateHolder certHolder = v1CertGen.build(sigGen);
		return new JcaX509CertificateConverter().getCertificate(certHolder);
	}
}
