package br.com.dextra.security.exceptions;

public class AuthenticationFailedException extends SecurityException {

	private static final long serialVersionUID = 4846962942986505063L;

	private boolean mustShowError;

	public AuthenticationFailedException(boolean mustShowError) {
		super();
		this.mustShowError = mustShowError;
	}

	public boolean mustShowError() {
		return mustShowError;
	}
}
