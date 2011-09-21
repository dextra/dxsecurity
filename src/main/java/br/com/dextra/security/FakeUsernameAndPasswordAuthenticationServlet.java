package br.com.dextra.security;

import javax.servlet.http.HttpServletRequest;

import br.com.dextra.security.exceptions.AuthenticationFailedException;

public class FakeUsernameAndPasswordAuthenticationServlet extends UsernameAndPasswordAuthenticationServlet {

	private static final long serialVersionUID = 3332521738662002286L;

	@Override
	protected AuthenticationData authenticate(HttpServletRequest req, String username, String password)
			throws AuthenticationFailedException {
		if (username != null && username.equals(password)) {
			return new AuthenticationData(username, configuration.getMyProvider());
		} else {
			throw new AuthenticationFailedException((username == null) ? false : true);
		}
	}
}
