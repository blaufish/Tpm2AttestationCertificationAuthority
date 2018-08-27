package blaufish.test.tpm2;

import java.io.File;
import java.nio.file.Files;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class AKCertDecryptCli {

	static final String ARG_IN_CREDENTIAL = "--in-credential";
	static final String ARG_IN_ENCRYPTED_CERT = "--in-encrypted-cert";
	static final String ARG_OUT_CERT = "--out-cert";

	public static void main(String[] args) throws Exception {
		Set<String> expected_arguments = new TreeSet<>();
		expected_arguments.add(ARG_IN_ENCRYPTED_CERT);
		expected_arguments.add(ARG_IN_CREDENTIAL);
		expected_arguments.add(ARG_OUT_CERT);
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
		byte[] key = Files.readAllBytes(new File(cmd.get(ARG_IN_CREDENTIAL)).toPath());
		byte[] encrypted = Files.readAllBytes(new File(cmd.get(ARG_IN_ENCRYPTED_CERT)).toPath());
		byte[] decrypted = AuthenticationKeyCertificateEncryption.decrypt(key, encrypted);
		Files.write(new File(cmd.get(ARG_OUT_CERT)).toPath(), decrypted);
	}
}
