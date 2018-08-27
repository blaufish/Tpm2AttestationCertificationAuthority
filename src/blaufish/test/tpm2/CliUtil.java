package blaufish.test.tpm2;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

class CliUtil {
	static Map<String, String> parse(String[] args, Set<String> expected, Set<String> required) {
		Map<String, String> map = new HashMap<>();
		for (String arg : args) {
			String[] split = arg.split("=");
			if (split.length != 2)
				throw new IllegalArgumentException("Illegal syntax: " + arg);
			if (map.containsKey(split[0]))
				throw new IllegalArgumentException("Repeated argument: " + arg);
			if (!expected.contains(split[0]))
				throw new IllegalArgumentException("Unknown argument: " + arg);
			map.put(split[0], split[1]);
		}
		for (String r : required)
			if (!map.containsKey(r)) {
				throw new IllegalArgumentException("Missing argument: " + r);
			}
		return map;
	}
}
