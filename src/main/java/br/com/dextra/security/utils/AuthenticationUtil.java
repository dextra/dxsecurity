package br.com.dextra.security.utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import br.com.dextra.security.AuthenticationData;
import br.com.dextra.security.configuration.CertificateRepository;

public class AuthenticationUtil {

	public static String sign(AuthenticationData data, CertificateRepository certificateRepository) {
		String authData = data.toString();

		String signature = sign(authData, certificateRepository);
		if (!verify(data, signature, certificateRepository)) {
			throw new RuntimeException("Missed public and private keys.");
		}

		return signature;
	}

	public static boolean verify(AuthenticationData authData, String signature, CertificateRepository certificateRepository) {
		try {
			Signature sig = Signature.getInstance("SHA1withDSA");
			sig.initVerify(certificateRepository.getPublicKeyFor(authData.getProvider()));
			sig.update(authData.toString().getBytes());
			return sig.verify(SignatureEncodingUtil.decode(signature));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	public static String sign(String data, CertificateRepository certificateRepository) {
		try {
			Signature sig = Signature.getInstance("SHA1withDSA");
			sig.initSign(certificateRepository.getPrivateKey());
			sig.update(data.getBytes());
			byte[] signature = sig.sign();

			return new String(SignatureEncodingUtil.encode(signature));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}
}
