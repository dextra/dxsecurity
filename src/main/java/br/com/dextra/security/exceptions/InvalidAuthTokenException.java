package br.com.dextra.security.exceptions;

import static br.com.dextra.security.utils.StringConcatUtil.concat;
import br.com.dextra.security.Credential;

public class InvalidAuthTokenException extends Exception {

	private static final long serialVersionUID = 3429938665478651312L;

	public InvalidAuthTokenException(Credential authData) {
		super(concat("Invalid token : ", authData));
	}

	public InvalidAuthTokenException(Exception e, String token) {
		super(concat("Invalid token : ", token), e);
	}

	public InvalidAuthTokenException(String token) {
		super(concat("Invalid token : ", token));
	}
}
