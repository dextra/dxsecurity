package br.com.dextra.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.text.ParseException;
import java.util.Comparator;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.dextra.security.configuration.Configuration;
import br.com.dextra.security.exceptions.ExpiredAuthTokenException;
import br.com.dextra.security.exceptions.InvalidAuthTokenException;
import br.com.dextra.security.exceptions.TimestampParsingException;
import br.com.dextra.security.utils.AuthenticationUtil;

public class AuthenticationFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

	private static final String AUTH_REQUEST_PARAMETER = "auth";

	private Configuration configuration;

	private static final Comparator<? super Cookie> cookieComparator = new Comparator<Cookie>() {
		@Override
		public int compare(Cookie o1, Cookie o2) {
			return (-1) * o1.getName().compareTo(o2.getName());
		}
	};

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		process((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	protected void process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String token = extractAuthTokenFrom(request);

		if (token == null) {
			sendError(request, response);
			return;
		}

		Credential credential;
		try {
			credential = processAndValidate(token);
			logger.info("Received authentication token : {}", credential);
		} catch (InvalidAuthTokenException e) {
			logger.warn("Invalid authentication token received.", e);
			expireCookies(request, response);
			sendError(request, response);
			return;
		} catch (ExpiredAuthTokenException e) {
			logger.warn("Invalid authentication token received.", e);
			expireCookies(request, response);
			sendExpiryError(request, response, token);
			return;
		} catch (Exception e) {
			logger.warn("Error while processing the received authentication token : " + token, e);
			expireCookies(request, response);
			sendError(request, response);
			return;
		}

		try {
			if (mustRenew(credential)) {
				expireCookies(request, response);
				credential = renew(credential, request, response);
			}
		} catch (Exception e) {
			logger.warn("Error while processing the received authentication token : " + token, e);
			sendError(request, response);
			return;
		}

		try {
			registerAuthenticationData(credential);
			chain.doFilter(request, response);
		} finally {
			deregisterAuthenticationData();
		}
	}

	public static void expireCookies(HttpServletRequest request, HttpServletResponse response) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().startsWith(AuthenticationServlet.AUTH_COOKIE_NAME)) {
					cookie.setMaxAge(0);
					cookie.setValue(null);
					cookie.setPath(AuthenticationServlet.generateCookiePath(request));
					response.addCookie(cookie);
				}
			}
		}
	}

	protected Credential renew(Credential credential, HttpServletRequest request, HttpServletResponse response)
			throws ParseException {
		credential = credential.renew();

		String token = AuthenticationUtil.sign(credential, configuration.getCertificateRepository());

		logger.info("Authentication token renew to : {}", credential);

		AuthenticationServlet.createAuthCookie(token, request, response, configuration.getCookieExpiryTimeout());

		return Credential.parse(token);
	}

	protected boolean mustRenew(Credential auth) {
		return getToday().getTime() - configuration.getRenewTimeout() > auth.getTimestamp().getTime();
	}

	protected Date getToday() {
		return new Date();
	}

	protected boolean expired(Credential credential) {
		long today = getToday().getTime();
		long timeout = configuration.getExpiryTimeout();
		long time = credential.getTimestamp().getTime();
		return today - timeout > time;
	}

	protected void deregisterAuthenticationData() {
		CredentialHolder.deregister();
	}

	protected void registerAuthenticationData(Credential auth) {
		CredentialHolder.register(auth);
	}

	protected Credential processAndValidate(String token) throws InvalidAuthTokenException, ExpiredAuthTokenException {
		try {
			Credential credential = Credential.parse(token);

			String provider = credential.getProvider();
			if (provider == null || !allowProvider(provider)) {
				throw new InvalidAuthTokenException(token);
			}

			if (expired(credential)) {
				throw new ExpiredAuthTokenException(credential);
			}

			if (AuthenticationUtil.verify(credential, credential.getSignature(),
					configuration.getCertificateRepository())) {
				return credential;
			} else {
				throw new InvalidAuthTokenException(credential);
			}
		} catch (TimestampParsingException e) {
			throw new InvalidAuthTokenException(e, token);
		}
	}

	protected boolean allowProvider(String provider) {
		return configuration.getAllowedProviders().contains(provider);
	}

	protected void sendError(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		configuration.getNotAuthenticatedHandler().sendResponse(req, resp);
	}

	protected void sendExpiryError(HttpServletRequest req, HttpServletResponse resp, String authToken)
			throws IOException {
		configuration.getAuthenticationExpiredHandler().sendResponse(req, resp);
	}

	protected String decode(String token) {
		try {
			String decodedToken = URLDecoder.decode(token, "UTF-8");

			decodedToken = decodedToken.replaceAll(" ", "+");

			return decodedToken;
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	protected String extractAuthTokenFrom(HttpServletRequest request) {
		String authToken = request.getParameter(AUTH_REQUEST_PARAMETER);
		if (authToken != null) {
			return decode(authToken);
		}

		Set<Cookie> cookiesFound = new TreeSet<Cookie>(cookieComparator);

		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().startsWith(AuthenticationServlet.AUTH_COOKIE_NAME)) {
					cookiesFound.add(cookie);
				}
			}
		}

		if (cookiesFound.size() > 0) {
			Cookie cookie = cookiesFound.iterator().next();
			return decode(cookie.getValue());
		} else {
			return null;
		}
	}

	@Override
	public void init(FilterConfig config) throws ServletException {
		String path = config.getInitParameter(Configuration.CONFIGURATION_FILE_KEY);
		if (path == null) {
			path = config.getServletContext().getInitParameter(Configuration.CONFIGURATION_FILE_KEY);
		}

		this.configuration = Configuration.buildFromFile(getClassLoaderForConfiguration(), path);

		logger.info("Configuration loaded : {}", configuration);
	}

	protected ClassLoader getClassLoaderForConfiguration() {
		return getClass().getClassLoader();
	}

	@Override
	public void destroy() {
	}

	public Configuration getConfiguration() {
		return configuration;
	}

	public void setConfiguration(Configuration configuration) {
		this.configuration = configuration;
	}
}
