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
import br.com.dextra.security.utils.AuthenticationUtil;

public class AuthenticationFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

	private static final String AUTH_REQUEST_PARAMETER = "auth";

	protected Configuration configuration;

	private static final Comparator<? super Cookie> cookieComparator = new Comparator<Cookie>() {
		@Override
		public int compare(Cookie o1, Cookie o2) {
			return (-1) * o1.getName().compareTo(o2.getName());
		}
	};

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		process((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	protected void process(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		String authToken = extractAuthTokenFrom(request);

		if (authToken == null) {
			sendError(request, response);
			return;
		}

		AuthenticationData auth;
		try {
			auth = processAndValidate(authToken);
			logger.info("Received authentication token (cookie) : {}", auth);
		} catch (InvalidAuthTokenException e) {
			logger.warn("Invalid authentication token received.", e);
			expireCookies(request, response);
			sendError(request, response);
			return;
		} catch (ExpiredAuthTokenException e) {
			logger.warn("Invalid authentication token received.", e);
			expireCookies(request, response);
			sendExpiryError(request, response, authToken);
			return;
		} catch (Exception e) {
			logger.warn("Error while processing the received authentication token : " + authToken, e);
			expireCookies(request, response);
			sendError(request, response);
			return;
		}

		try {
			if (mustRenew(auth)) {
				expireCookies(request, response);
				auth = renew(auth, request, response);
			}
		} catch (Exception e) {
			logger.warn("Error while processing the received authentication token : " + authToken, e);
			sendError(request, response);
			return;
		}

		try {
			registerAuthenticationData(auth);
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

	protected AuthenticationData renew(AuthenticationData auth, HttpServletRequest request, HttpServletResponse response)
			throws ParseException {
		auth = auth.renew();

		String authData = AuthenticationUtil.sign(auth, configuration.getCertificateRepository());

		logger.info("Authentication token (cookie) renew to : {}", auth);

		AuthenticationServlet.createAuthCookie(authData, request, response, configuration.getCookieExpiryTimeout());

		return AuthenticationData.parse(authData);
	}

	protected boolean mustRenew(AuthenticationData auth) {
		return getToday().getTime() - configuration.getRenewTimeout() > auth.getTimestamp().getTime();
	}

	protected Date getToday() {
		return new Date();
	}

	protected boolean expired(AuthenticationData auth) {
		return getToday().getTime() - configuration.getExpiryTimeout() > auth.getTimestamp().getTime();
	}

	protected void deregisterAuthenticationData() {
		AuthenticationDataHolder.deregister();
	}

	protected void registerAuthenticationData(AuthenticationData auth) {
		AuthenticationDataHolder.register(auth);
	}

	protected AuthenticationData processAndValidate(String authToken) throws InvalidAuthTokenException, ExpiredAuthTokenException {
		try {
			AuthenticationData authData = AuthenticationData.parse(authToken);

			String provider = authData.getProvider();
			if (provider == null || !allowProvider(provider)) {
				throw new InvalidAuthTokenException(authToken);
			}

			if (expired(authData)) {
				throw new ExpiredAuthTokenException(authData);
			}

			if (AuthenticationUtil.verify(authData, authData.getSignature(), configuration.getCertificateRepository())) {
				return authData;
			} else {
				throw new InvalidAuthTokenException(authData);
			}
		} catch (ParseException e) {
			throw new InvalidAuthTokenException(e, authToken);
		}
	}

	protected boolean allowProvider(String provider) {
		return configuration.getAllowedProviders().contains(provider);
	}

	protected void sendError(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		configuration.getNotAuthenticatedHandler().sendResponse(req, resp);
	}

	protected void sendExpiryError(HttpServletRequest req, HttpServletResponse resp, String authToken) throws IOException {
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
}
