package br.com.dextra.security;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.dextra.security.configuration.Configuration;
import br.com.dextra.security.exceptions.AuthenticationFailedException;
import br.com.dextra.security.utils.AuthenticationUtil;

/**
 * The authentication servlet is responsible for validating the user credentials present on the
 * {@link HttpServletRequest}. The method that does this is {@link #authenticate(HttpServletRequest)}. If a
 * {@link Credential} is returned from this method a signed token is generated and returned to the client as a cookie.
 * After that, the {@link Configuration#getAuthenticationSuccessHandler()} is executed.
 * 
 * If the authentication fail and the method {@link #authenticate(HttpServletRequest)} throws
 * {@link AuthenticationFailedException} with the <code>mustShowError</code> parameter with value <code>true</code>, the
 * cookie is not created and the {@link Configuration#getAuthenticationFailedHandler()} is executed. If the parameter
 * <code>mustShowError</code> is <code>false</code>, the cookie is also not created and the
 * {@link Configuration#getNotAuthenticatedHandler()} is executed.
 */
public abstract class AuthenticationServlet extends HttpServlet {

	private static final long serialVersionUID = -5794836444983032927L;

	private static final Logger logger = LoggerFactory.getLogger(AuthenticationServlet.class);

	public static final String CLEAR_CERTIFICATE_REPOSITORY_CACHE_KEY = "certificateRepository.clearCaches";
	public static final String AUTH_COOKIE_NAME = "auth";

	protected Configuration configuration;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		startAuthentication(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		startAuthentication(req, resp);
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
		String path = config.getInitParameter(Configuration.CONFIGURATION_FILE_KEY);
		if (path == null) {
			path = config.getServletContext().getInitParameter(Configuration.CONFIGURATION_FILE_KEY);
		}

		this.configuration = Configuration.buildFromFile(getClassLoaderForConfiguration(), path);

		logger.info("Configuration loaded : {}", configuration);

		super.init(config);
	}

	protected ClassLoader getClassLoaderForConfiguration() {
		return getClass().getClassLoader();
	}

	protected void startAuthentication(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		CredentialHolder.deregister();

		clearCachesIfRequestParameter(req);

		try {
			Credential credential = authenticate(req);
			String token = credential.toString();

			logger.info("User authenticated as {}", token);

			String signature = generateAuthenticationDataString(credential);
			credential.setSignature(signature);
			CredentialHolder.register(credential);

			createAuthCookie(credential.toStringFull(), req, resp, configuration.getCookieExpiryTimeout());

			sendSuccess(token, req, resp);
		} catch (AuthenticationFailedException e) {
			logger.debug("Authentication failed.", e);
			sendError(e, req, resp);
		}
	}

	private void clearCachesIfRequestParameter(HttpServletRequest req) {
		if (req.getParameter(CLEAR_CERTIFICATE_REPOSITORY_CACHE_KEY) != null) {
			configuration.getCertificateRepository().clearCaches();
		}
	}

	protected void sendError(AuthenticationFailedException e, HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		if (e.mustShowError()) {
			configuration.getAuthenticationFailedHandler().sendResponse(req, resp);
		} else {
			configuration.getNotAuthenticatedHandler().sendResponse(req, resp);
		}
	}

	protected void sendSuccess(String token, HttpServletRequest req, HttpServletResponse resp) throws IOException {
		configuration.getAuthenticationSuccessHandler().sendResponse(req, resp);
	}

	public static void createAuthCookie(String token, HttpServletRequest req, HttpServletResponse resp,
			int cookieExpiryTimeout) {
		Cookie authCookie = new Cookie(generateCookieName(), token);

		String path = generateCookiePath(req);

		authCookie.setPath(path);
		if (cookieExpiryTimeout > 0) {
			authCookie.setMaxAge(cookieExpiryTimeout);
		}

		resp.addCookie(authCookie);
	}

	public static String generateCookiePath(HttpServletRequest req) {
		String path = req.getContextPath();
		if (!path.endsWith("/")) {
			path += "/";
		}
		return path;
	}

	public static String generateCookieName() {
		return AUTH_COOKIE_NAME + System.currentTimeMillis();
	}

	protected String generateAuthenticationDataString(Credential credential) {
		return AuthenticationUtil.sign(credential, configuration.getCertificateRepository());
	}

	public Configuration getConfiguration() {
		return configuration;
	}

	public void setConfiguration(Configuration configuration) {
		this.configuration = configuration;
	}

	/**
	 * This method should be implemented to authenticate the user accordingly to the application's business rules. If
	 * the authentication fail, this method should throw {@link AuthenticationFailedException}. If the authentication is
	 * successful a {@link Credential} or a class that extends it should be returned.
	 * 
	 * @param req
	 *            The full HTTP request.
	 * @return A valid {@link Credential}. It can be a class that extends {@link Credential}.
	 * @throws AuthenticationFailedException
	 *             If the authentication fail.
	 */
	protected abstract Credential authenticate(HttpServletRequest req) throws AuthenticationFailedException;
}
