package br.com.dextra.security.configuration;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface CertificateRepository {

	public PrivateKey getPrivateKey();

	public PublicKey getPublicKeyFor(String provider);

	public void clearCaches();
}
