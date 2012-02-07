package br.com.dextra.security;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import br.com.dextra.security.exceptions.TimestampParsingException;

public class CredentialTest {

	private static final DateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");

	@Test
	@SuppressWarnings("serial")
	public void testCreateNewCredential() {
		Credential credential = new Credential("test", "Test") {

			@Override
			protected Date getToday() {
				return date("07/02/2012");
			}
		};

		Assert.assertEquals("test|Test|20120207.000000000", credential.toString());
	}

	@Test(expected = TimestampParsingException.class)
	public void testCreateCredentialWithWrongTimestampFormat() {
		new Credential("a", "Services", "20110706", "MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g==",
				"a|Services|20110706.105225185|MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g==");
	}

	@Test
	public void testCreateCredentialFromToken() {
		Credential credential = new Credential("a", "Services", "20110706.105225185",
				"MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g==",
				"a|Services|20110706.105225185|MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g==");

		Assert.assertEquals("a", credential.getUsername());
		Assert.assertEquals("Services", credential.getProvider());
		Assert.assertEquals(Credential.dateFormat.parseDateTime("20110706.105225185").toDate(),
				credential.getTimestamp());
	}

	@Test
	public void testRenewCredential() throws InterruptedException {
		Credential credential = new Credential("a", "Services");
		Date firstTimestamp = credential.getTimestamp();

		Thread.sleep(100);
		
		credential = credential.renew();
		Date secondTimestamp = credential.getTimestamp();

		Assert.assertEquals("a", credential.getUsername());
		Assert.assertEquals("Services", credential.getProvider());
		Assert.assertTrue(firstTimestamp.before(secondTimestamp));
	}

	@Test
	public void testSplit() {
		String[] tokens = Credential
				.splitTokens("a|Services|20110706.105225185|MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g==");

		Assert.assertEquals(4, tokens.length);
		Assert.assertEquals("a", tokens[0]);
		Assert.assertEquals("Services", tokens[1]);
		Assert.assertEquals("20110706.105225185", tokens[2]);
		Assert.assertEquals("MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g==", tokens[3]);
	}

	@Test
	public void testSplitWithSpecialCharacters() {
		String[] tokens = Credential
				.splitTokens("a|Services|20110706.105225185|MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgE|hy+yjh9L4fbvvH2wT3hq0g==");

		Assert.assertEquals(4, tokens.length);
		Assert.assertEquals("a", tokens[0]);
		Assert.assertEquals("Services", tokens[1]);
		Assert.assertEquals("20110706.105225185", tokens[2]);
		Assert.assertEquals("MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgE|hy+yjh9L4fbvvH2wT3hq0g==", tokens[3]);
	}

	@Test
	public void testSplitWithSpecialCharacters2() {
		String[] tokens = Credential
				.splitTokens("userdextra|SOCC|20110727.123610357|MCwCFDDxz4OTYlfc3Dd26QK1USV53miHAhQQS+vxNEPr/51u9jGpBQAwMBFv2g==");

		Assert.assertEquals(4, tokens.length);
		Assert.assertEquals("userdextra", tokens[0]);
		Assert.assertEquals("SOCC", tokens[1]);
		Assert.assertEquals("20110727.123610357", tokens[2]);
		Assert.assertEquals("MCwCFDDxz4OTYlfc3Dd26QK1USV53miHAhQQS+vxNEPr/51u9jGpBQAwMBFv2g==", tokens[3]);
	}

	@Test
	public void testSplitWithoutTrailingCharacters() {
		String[] tokens = Credential
				.splitTokens("a|Services|20110706.105225185|MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g");

		Assert.assertEquals(4, tokens.length);
		Assert.assertEquals("a", tokens[0]);
		Assert.assertEquals("Services", tokens[1]);
		Assert.assertEquals("20110706.105225185", tokens[2]);
		Assert.assertEquals("MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g==", tokens[3]);
	}

	@Test
	public void testDateParseAndFormat() throws ParseException {
		String originalDate = "20110706.111513655";

		Date date = Credential.dateFormat.parseDateTime(originalDate).toDate();
		String result = Credential.dateFormat.print(date.getTime());

		Assert.assertEquals(originalDate, result);
	}

	protected Date date(String value) {
		try {
			return dateFormat.parse(value);
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}
}
