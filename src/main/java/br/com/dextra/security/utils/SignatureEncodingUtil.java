package br.com.dextra.security.utils;

import org.apache.commons.codec.binary.Base64;

public class SignatureEncodingUtil {

	public static byte[] encode(byte[] signature) {
		return Base64.encodeBase64(signature);
	}

	public static byte[] decode(String signature) {
		return Base64.decodeBase64(signature.getBytes());
	}
}
