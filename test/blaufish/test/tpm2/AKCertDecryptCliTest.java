package blaufish.test.tpm2;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.ProcessBuilder.Redirect;

import org.junit.jupiter.api.Test;

class AKCertDecryptCliTest {

	@Test
	void test() throws Exception {
		ProcessBuilder pb = new ProcessBuilder();
		Process p = pb.command("./test/cli_ak_decrypt.sh").redirectError(Redirect.INHERIT).redirectOutput(Redirect.INHERIT)
				.start();
		p.waitFor();
		assertEquals(0, p.exitValue());
	}

}
