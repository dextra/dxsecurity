package br.com.dextra.security.utils;

public class StringConcatUtil {

	public static String concat(Object... values) {
		StringBuilder result = new StringBuilder();

		for (Object value : values) {
			result.append(value);
		}

		return result.toString();
	}
}
