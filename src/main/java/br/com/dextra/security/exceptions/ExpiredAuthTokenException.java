package br.com.dextra.security.exceptions;

import br.com.dextra.security.AuthenticationData;
import static br.com.dextra.security.utils.StringConcatUtil.concat;

public class ExpiredAuthTokenException extends SecurityException {

	private static final long serialVersionUID = 9180746328888903346L;

	public ExpiredAuthTokenException(AuthenticationData authData) {
		super(concat("Expired auth token : ", authData));
	}
}
