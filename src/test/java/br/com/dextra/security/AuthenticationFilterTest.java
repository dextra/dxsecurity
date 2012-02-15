package br.com.dextra.security;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;

import br.com.dextra.security.configuration.Configuration;
import br.com.dextra.security.configuration.ForbiddenResponseHandler;
import br.com.dextra.security.configuration.StringBase64CertificateRepository;
import br.com.dextra.security.utils.AuthenticationUtil;
import br.com.dextra.security.utils.GenerateKeysUtil;

public class AuthenticationFilterTest {

	@Test
	public void testAuthenticatedUser() throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
			ServletException {
		Configuration config = new Configuration();

		StringBase64CertificateRepository certificateRepository = GenerateKeysUtil.generateKeys("Test");

		config.setAllowedProviders("Test");
		config.setNotAuthenticatedHandler(new ForbiddenResponseHandler());
		config.setCertificateRepository(certificateRepository);
		config.setCookieExpiryTimeout(1000);
		config.setExpiryTimeout(1000);
		config.setMyProvider("Test");
		config.setRenewTimeout(1000);

		AuthenticationFilter filter = new AuthenticationFilter();
		filter.setConfiguration(config);

		Credential credential = new Credential("test", "Test");
		String signature = AuthenticationUtil.sign(credential, certificateRepository);
		credential.setSignature(signature);

		HttpServletRequestStub req = new HttpServletRequestStub();
		req.addCookie(new Cookie(AuthenticationServlet.generateCookieName(), credential.toStringFull()));
		HttpServletResponseStub resp = new HttpServletResponseStub();
		FilterChainStub chain = new FilterChainStub();

		filter.doFilter(req, resp, chain);

		Assert.assertTrue(chain.wasExecuted());
		Assert.assertEquals(-1, resp.getError());
	}

	@Test
	public void testUnauthenticatedUser() throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
			ServletException {
		Configuration config = new Configuration();

		StringBase64CertificateRepository certificateRepository = GenerateKeysUtil.generateKeys("Test");

		config.setAllowedProviders("Test");
		config.setNotAuthenticatedHandler(new ForbiddenResponseHandler());
		config.setCertificateRepository(certificateRepository);
		config.setCookieExpiryTimeout(1000);
		config.setExpiryTimeout(1000);
		config.setMyProvider("Test");
		config.setRenewTimeout(1000);

		AuthenticationFilter filter = new AuthenticationFilter();
		filter.setConfiguration(config);

		HttpServletRequestStub req = new HttpServletRequestStub();
		HttpServletResponseStub resp = new HttpServletResponseStub();
		FilterChainStub chain = new FilterChainStub();

		filter.doFilter(req, resp, chain);

		Assert.assertFalse(chain.wasExecuted());
		Assert.assertEquals(ForbiddenResponseHandler.HTTP_ERROR_CODE, resp.getError());
	}

	@Test
	public void testUnallowedProvider() throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
			ServletException {
		Configuration config = new Configuration();

		StringBase64CertificateRepository certificateRepository = GenerateKeysUtil.generateKeys("Test");
		certificateRepository.configurePublicKey("OtherProvider",
				new String(Base64.encodeBase64(certificateRepository.getPublicKeyFor("Test").getEncoded())));

		config.setAllowedProviders("Test");
		config.setNotAuthenticatedHandler(new ForbiddenResponseHandler());
		config.setCertificateRepository(certificateRepository);
		config.setCookieExpiryTimeout(1000);
		config.setExpiryTimeout(1000);
		config.setMyProvider("Test");
		config.setRenewTimeout(1000);

		AuthenticationFilter filter = new AuthenticationFilter();
		filter.setConfiguration(config);

		Credential credential = new Credential("test", "OtherProvider");
		String signature = AuthenticationUtil.sign(credential, certificateRepository);
		credential.setSignature(signature);

		HttpServletRequestStub req = new HttpServletRequestStub();
		req.addCookie(new Cookie(AuthenticationServlet.generateCookieName(), credential.toStringFull()));
		HttpServletResponseStub resp = new HttpServletResponseStub();
		FilterChainStub chain = new FilterChainStub();

		filter.doFilter(req, resp, chain);

		Assert.assertFalse(chain.wasExecuted());
		Assert.assertEquals(ForbiddenResponseHandler.HTTP_ERROR_CODE, resp.getError());
	}

	@Test
	public void testExpiredCredential() throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
			ServletException, InterruptedException {
		Configuration config = new Configuration();

		StringBase64CertificateRepository certificateRepository = GenerateKeysUtil.generateKeys("Test");

		config.setAllowedProviders("Test");
		config.setAuthenticationExpiredHandler(new ForbiddenResponseHandler());
		config.setCertificateRepository(certificateRepository);
		config.setCookieExpiryTimeout(1000);
		config.setExpiryTimeout(10);
		config.setMyProvider("Test");
		config.setRenewTimeout(1000);

		AuthenticationFilter filter = new AuthenticationFilter();
		filter.setConfiguration(config);

		Credential credential = new Credential("test", "Test");
		String signature = AuthenticationUtil.sign(credential, certificateRepository);
		credential.setSignature(signature);

		HttpServletRequestStub req = new HttpServletRequestStub();
		req.addCookie(new Cookie(AuthenticationServlet.generateCookieName(), credential.toStringFull()));
		HttpServletResponseStub resp = new HttpServletResponseStub();
		FilterChainStub chain = new FilterChainStub();

		Thread.sleep(100);

		filter.doFilter(req, resp, chain);

		Assert.assertFalse(chain.wasExecuted());
		Assert.assertEquals(ForbiddenResponseHandler.HTTP_ERROR_CODE, resp.getError());
	}

	@Test
	public void testCredentialRenew() throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
			ServletException, InterruptedException {
		Configuration config = new Configuration();

		StringBase64CertificateRepository certificateRepository = GenerateKeysUtil.generateKeys("Test");

		config.setAllowedProviders("Test");
		config.setCertificateRepository(certificateRepository);
		config.setCookieExpiryTimeout(10000);
		config.setExpiryTimeout(10000);
		config.setMyProvider("Test");
		config.setRenewTimeout(10);

		AuthenticationFilter filter = new AuthenticationFilter();
		filter.setConfiguration(config);

		Credential credential = new Credential("test", "Test");
		String signature = AuthenticationUtil.sign(credential, certificateRepository);
		credential.setSignature(signature);

		HttpServletRequestStub req = new HttpServletRequestStub();
		req.addCookie(new Cookie(AuthenticationServlet.generateCookieName(), credential.toStringFull()));
		HttpServletResponseStub resp = new HttpServletResponseStub();
		FilterChainStub chain = new FilterChainStub();

		Thread.sleep(100);

		filter.doFilter(req, resp, chain);

		Assert.assertTrue(chain.wasExecuted());
		Assert.assertEquals(-1, resp.getError());
		Assert.assertEquals(2, resp.getCookies().size());

		String token = null;
		for (Cookie cookie : resp.getCookies()) {
			if (cookie.getValue() != null) {
				token = cookie.getValue();
			}
		}
		Assert.assertNotNull(token);
		Assert.assertTrue(token.startsWith("test|Test|"));
	}
}
