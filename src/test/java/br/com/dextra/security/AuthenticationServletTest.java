package br.com.dextra.security;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.junit.Test;

import br.com.dextra.security.configuration.Configuration;
import br.com.dextra.security.configuration.ForbiddenResponseHandler;
import br.com.dextra.security.configuration.RedirectResponseHandler;
import br.com.dextra.security.configuration.StringBase64CertificateRepository;
import br.com.dextra.security.configuration.WriteTokenOnResponseResponseHandler;
import br.com.dextra.security.exceptions.AuthenticationFailedException;
import br.com.dextra.security.utils.GenerateKeysUtil;

public class AuthenticationServletTest {

	@Test
	@SuppressWarnings("serial")
	public void testSuccessAuthentication() throws ServletException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException {
		Configuration config = new Configuration();

		StringBase64CertificateRepository certificateRepository = GenerateKeysUtil.generateKeys("Test");

		config.setAllowedProviders("Test");
		config.setAuthenticationSuccessHandler(new WriteTokenOnResponseResponseHandler());
		config.setCertificateRepository(certificateRepository);
		config.setCookieExpiryTimeout(1000);
		config.setExpiryTimeout(1000);
		config.setMyProvider("Test");
		config.setRenewTimeout(1000);

		AuthenticationServlet servlet = new AuthenticationServlet() {

			@Override
			protected Credential authenticate(HttpServletRequest req) throws AuthenticationFailedException {
				return new Credential("test", "Test");
			}
		};
		servlet.setConfiguration(config);

		HttpServletRequestStub req = new HttpServletRequestStub();
		HttpServletResponseStub resp = new HttpServletResponseStub();

		servlet.doGet(req, resp);

		Assert.assertEquals(-1, resp.getError());
		Assert.assertNull(resp.getRedirect());
		Assert.assertTrue(resp.getResponse().startsWith("test|Test|"));
		Assert.assertTrue(CredentialHolder.get().toString().startsWith("test|Test|"));
	}

	@Test
	@SuppressWarnings("serial")
	public void testFailedAuthenticationWithForbidden() throws ServletException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException {
		Configuration config = new Configuration();

		StringBase64CertificateRepository certificateRepository = GenerateKeysUtil.generateKeys("Test");

		config.setAllowedProviders("Test");
		config.setAuthenticationFailedHandler(new ForbiddenResponseHandler());
		config.setCertificateRepository(certificateRepository);
		config.setCookieExpiryTimeout(1000);
		config.setExpiryTimeout(1000);
		config.setMyProvider("Test");
		config.setRenewTimeout(1000);

		AuthenticationServlet servlet = new AuthenticationServlet() {

			@Override
			protected Credential authenticate(HttpServletRequest req) throws AuthenticationFailedException {
				throw new AuthenticationFailedException(true);
			}
		};
		servlet.setConfiguration(config);

		HttpServletRequestStub req = new HttpServletRequestStub();
		HttpServletResponseStub resp = new HttpServletResponseStub();

		servlet.doGet(req, resp);

		Assert.assertEquals(403, resp.getError());
		Assert.assertNull(resp.getRedirect());
		Assert.assertEquals("", resp.getResponse());
		Assert.assertNull(CredentialHolder.get());
	}

	@Test
	@SuppressWarnings("serial")
	public void testFailedAuthenticationWithRedirect() throws ServletException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException {
		Configuration config = new Configuration();

		StringBase64CertificateRepository certificateRepository = GenerateKeysUtil.generateKeys("Test");

		config.setAllowedProviders("Test");
		config.setNotAuthenticatedHandler(new RedirectResponseHandler("/redirectTo"));
		config.setCertificateRepository(certificateRepository);
		config.setCookieExpiryTimeout(1000);
		config.setExpiryTimeout(1000);
		config.setMyProvider("Test");
		config.setRenewTimeout(1000);

		AuthenticationServlet servlet = new AuthenticationServlet() {

			@Override
			protected Credential authenticate(HttpServletRequest req) throws AuthenticationFailedException {
				throw new AuthenticationFailedException(false);
			}
		};
		servlet.setConfiguration(config);

		HttpServletRequestStub req = new HttpServletRequestStub();
		HttpServletResponseStub resp = new HttpServletResponseStub();

		servlet.doGet(req, resp);

		Assert.assertEquals(-1, resp.getError());
		Assert.assertEquals("/redirectTo", resp.getRedirect());
		Assert.assertEquals("", resp.getResponse());
		Assert.assertNull(CredentialHolder.get());
	}
}
