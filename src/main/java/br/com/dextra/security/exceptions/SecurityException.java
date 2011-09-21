package br.com.dextra.security.exceptions;

public abstract class SecurityException extends RuntimeException {

	private static final long serialVersionUID = -967426930821906020L;

	public SecurityException() {
		super();
	}

	public SecurityException(String message, Throwable cause) {
		super(message, cause);
	}

	public SecurityException(String message) {
		super(message);
	}

	public SecurityException(Throwable cause) {
		super(cause);
	}
}
