package br.com.dextra.security.configuration;

public class ConfigurationException extends RuntimeException {

	private static final long serialVersionUID = 7666499714266701317L;

	public ConfigurationException(Throwable cause) {
		super(cause);
	}

	public ConfigurationException(String message) {
		super(message);
	}
}
