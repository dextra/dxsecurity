package br.com.dextra.security.configuration;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.dextra.security.exceptions.InvalidKeyPathException;

public class FileSystemCertificateRepository implements CertificateRepository {

	private static final Logger logger = LoggerFactory.getLogger(FileSystemCertificateRepository.class);

	private final String privateKeyPath;
	private final String publicKeysPath;
	private PrivateKey privateKey;
	private Map<String, PublicKey> publicKeys = new HashMap<String, PublicKey>();

	public FileSystemCertificateRepository(String privateKeyPath, String publicKeysPath) {
		super();
		this.privateKeyPath = processEnvironmentVariables(privateKeyPath);
		this.publicKeysPath = processEnvironmentVariables(publicKeysPath);
	}

	public static String processEnvironmentVariables(String keyPath) {
		Map<String, String> env = System.getenv();

		for (Entry<String, String> entry : env.entrySet()) {
			keyPath = keyPath.replace("$" + entry.getKey(), entry.getValue());
		}

		return keyPath;
	}

	public PrivateKey getPrivateKey() {
		if (privateKey != null) {
			return privateKey;
		}

		try {
			byte[] encKey = loadKeyFor(privateKeyPath);
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encKey);
			KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

			privateKey = keyFactory.generatePrivate(privateKeySpec);

			return privateKey;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	public PublicKey getPublicKeyFor(String alias) {
		PublicKey publicKey = publicKeys.get(alias);
		if (publicKey != null) {
			return publicKey;
		}

		try {
			byte[] encKey = loadKeyFor(generatePublicKeyPath(alias));
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
			KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
			publicKey = keyFactory.generatePublic(pubKeySpec);

			publicKeys.put(alias, publicKey);

			return publicKey;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	public void clearCaches() {
		this.privateKey = null;
		this.publicKeys.clear();
	}

	private byte[] loadKeyFor(String path) {
		FileInputStream fis = null;
		try {
			logger.debug("Loading key {}.", path);

			fis = new FileInputStream(path);
			BufferedInputStream bis = new BufferedInputStream(fis);

			ByteArrayOutputStream out = new ByteArrayOutputStream();

			IOUtils.copy(bis, out);

			bis.close();
			fis.close();

			return out.toByteArray();
		} catch (IOException e) {
			logger.error(MessageFormat.format("Key not found : {0}", path), e);
			throw new InvalidKeyPathException(path);
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
				}
			}
		}
	}

	private String generatePublicKeyPath(String alias) {
		StringBuilder url = new StringBuilder();
		url.append(publicKeysPath);
		url.append("/");
		url.append(alias);
		return url.toString();
	}

	public String getPrivateKeyPath() {
		return privateKeyPath;
	}

	public String getPublicKeysPath() {
		return publicKeysPath;
	}
}
