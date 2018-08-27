package blaufish.test.tpm2;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import blaufish.test.tpm2.Tpm2AttestationCA.TupleForTpm;

public class Tpm2AttestationCACli {

	static final String ARG_OUT_TPM_CREDENTIAL = "--out-tpm-credential";
	static final String ARG_OUT_TPM_AKCERT_ENCRYPTED = "--out-tpm-akcert-encrypted";
	static final String ARG_OUT_CACERT = "--out-cacert";
	static final String ARG_IN_AKPUB = "--in-akpub";
	static final String ARG_IN_AKNAME = "--in-akname";
	static final String ARG_IN_EKCERT = "--in-ekcert";
	static final String ARG_IN_TPM_MANUFACTURER_CERT = "--in-tpm-manufacturer-cert";


	static X509Certificate loadCertificate(String certificateFile) throws CertificateException, FileNotFoundException {
		return (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new FileInputStream(certificateFile));
	}

	public static void main(String[] args) throws Exception {
		Set<String> expected_arguments = new TreeSet<>();
		expected_arguments.add(ARG_IN_TPM_MANUFACTURER_CERT);
		expected_arguments.add(ARG_IN_EKCERT);
		expected_arguments.add(ARG_IN_AKNAME);
		expected_arguments.add(ARG_IN_AKPUB);
		expected_arguments.add(ARG_OUT_CACERT);
		expected_arguments.add(ARG_OUT_TPM_AKCERT_ENCRYPTED);
		expected_arguments.add(ARG_OUT_TPM_CREDENTIAL);
		Map<String, String> cmd;
		try {
			cmd = CliUtil.parse(args, expected_arguments, expected_arguments);
		} catch (IllegalArgumentException e) {
			System.out.println("ERROR: " + e.getMessage());
			System.out.println("Usage: " + Tpm2AttestationCACli.class.getCanonicalName());
			for (String s : expected_arguments) {
				System.out.println("  " + s + "=value");
			}
			System.exit(1);
			return;
		}
		X509Certificate manufacturerCertificate = loadCertificate(cmd.get(ARG_IN_TPM_MANUFACTURER_CERT));
		Tpm2AttestationCA ca = Tpm2AttestationCA.build(manufacturerCertificate);
		X509Certificate endorsementKeyCertificate = loadCertificate(cmd.get(ARG_IN_EKCERT));
		byte[] caCert = ca.getAuthorityCertificate().getEncoded();
		byte[] akname = Files.readAllBytes(new File(cmd.get(ARG_IN_AKNAME)).toPath());
		byte[] akpub = Files.readAllBytes(new File(cmd.get(ARG_IN_AKPUB)).toPath());
		TupleForTpm tpmTuple = ca.generateAkCert(endorsementKeyCertificate, akpub, akname);
		Files.write(new File(cmd.get(ARG_OUT_TPM_AKCERT_ENCRYPTED)).toPath(), tpmTuple.getEncryptedAkCertificate());
		Files.write(new File(cmd.get(ARG_OUT_TPM_CREDENTIAL)).toPath(), tpmTuple.getTpmCredential());
		Files.write(new File(cmd.get(ARG_OUT_CACERT)).toPath(), caCert);
	}
}
