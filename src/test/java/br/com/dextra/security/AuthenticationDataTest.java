package br.com.dextra.security;

import java.text.ParseException;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

public class AuthenticationDataTest {

	@Test
	public void testSplit() {
		String[] tokens = AuthenticationData
				.splitTokens("a|Services|20110706.105225185|MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g==");

		Assert.assertEquals(4, tokens.length);
		Assert.assertEquals("a", tokens[0]);
		Assert.assertEquals("Services", tokens[1]);
		Assert.assertEquals("20110706.105225185", tokens[2]);
		Assert.assertEquals("MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgEehy+yjh9L4fbvvH2wT3hq0g==", tokens[3]);
	}

	@Test
	public void testSplitWithSpecialCharacters() {
		String[] tokens = AuthenticationData
				.splitTokens("a|Services|20110706.105225185|MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgE|hy+yjh9L4fbvvH2wT3hq0g==");

		Assert.assertEquals(4, tokens.length);
		Assert.assertEquals("a", tokens[0]);
		Assert.assertEquals("Services", tokens[1]);
		Assert.assertEquals("20110706.105225185", tokens[2]);
		Assert.assertEquals("MCwCFFN7c9HrHVMe6s7Aru2C54SDxrOxAhRVXgE|hy+yjh9L4fbvvH2wT3hq0g==", tokens[3]);
	}

	@Test
	public void testSplitWithSpecialCharacters2() {
		String[] tokens = AuthenticationData
				.splitTokens("userdextra|SOCC|20110727.123610357|MCwCFDDxz4OTYlfc3Dd26QK1USV53miHAhQQS+vxNEPr/51u9jGpBQAwMBFv2g==");

		Assert.assertEquals(4, tokens.length);
		Assert.assertEquals("userdextra", tokens[0]);
		Assert.assertEquals("SOCC", tokens[1]);
		Assert.assertEquals("20110727.123610357", tokens[2]);
		Assert.assertEquals("MCwCFDDxz4OTYlfc3Dd26QK1USV53miHAhQQS+vxNEPr/51u9jGpBQAwMBFv2g==", tokens[3]);
	}

	@Test
	public void testSplitWithoutTrailingCharacters() {
		String[] tokens = AuthenticationData
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

		Date date = AuthenticationData.dateFormat.parseDateTime(originalDate).toDate();
		String result = AuthenticationData.dateFormat.print(date.getTime());

		Assert.assertEquals(originalDate, result);
	}
}
