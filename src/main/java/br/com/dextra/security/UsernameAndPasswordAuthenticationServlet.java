package br.com.dextra.security;

import javax.servlet.http.HttpServletRequest;

import br.com.dextra.security.exceptions.AuthenticationFailedException;

public abstract class UsernameAndPasswordAuthenticationServlet extends AuthenticationServlet {

	private static final long serialVersionUID = -7593983489500863831L;

	private static final String USERNAME_KEY = "username";
	private static final String PASSWORD_KEY = "password";

	@Override
	protected Credential authenticate(HttpServletRequest req) throws AuthenticationFailedException {
		String username = req.getParameter(USERNAME_KEY);
		String password = req.getParameter(PASSWORD_KEY);

		return authenticate(req, username, password);
	}

	protected abstract Credential authenticate(HttpServletRequest req, String username, String password)
			throws AuthenticationFailedException;
}
