package blaufish.test.tpm2;

public class Hexdump {
	public static StringBuilder hexdump(String name, byte[] blob) {
		StringBuilder sb = new StringBuilder();
		sb.append(name).append(System.lineSeparator()).append("==========");
		for (int i = 0; i < blob.length; i++) {
			if (i % 16 == 0) {
				sb.append(System.lineSeparator());
				sb.append(String.format("%04x: ", i));
			}
			sb.append(String.format("%02x", blob[i] & 0xFF));
		}
		sb.append(System.lineSeparator());		
		return sb;
	}
}
