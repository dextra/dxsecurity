package br.com.dextra.security.utils;

import static org.junit.Assert.*;

import org.junit.Test;

public class StringConcatUtilTest {

	@Test
	public void testLongString() {
		String result = StringConcatUtil.concat("a", "b", "c", "d");
		assertEquals("abcd", result);
	}

	@Test
	public void testEmptyString() {
		String result = StringConcatUtil.concat();
		assertEquals("", result);
	}
}
