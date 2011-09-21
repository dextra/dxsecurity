package br.com.dextra.security.utils;

import org.junit.Assert;
import org.junit.Test;

public class SignatureEncodingUtilTest {

	@Test
	public void testEncoding() {
		byte[] b = new byte[] { 26, -92, -112, -72, -109, -113, -123, 87, 61, 122, 73, 58, 12, -41, -43, -102, 36, 109, -87, -14, -46, 55,
				-36, 120, -65, -116, 116, -21, 98, 127, -9, -113, -74, -120, 65, 117, 45, 99, -104, 0, -29, 56, -3, -93, 22, -5, -60, -17,
				-42, 21, 103, -52, -8, 67, -106, 6, 80, -66, -111, 11, 30, -100, -70, -14, -56, 117, 101, -65, -55, 73, -14, -27, -23, -95,
				30, 11, -82, -13, -107, 19, 18, 74, -53, 87, 117, 38, 11, 53, -44, -96, -49, -51, 59, -46, 82, 9, 120, 117, 99, -35 };

		String s = new String(SignatureEncodingUtil.encode(b));

		Assert.assertEquals(
				"GqSQuJOPhVc9ekk6DNfVmiRtqfLSN9x4v4x062J/94+2iEF1LWOYAOM4/aMW+8Tv1hVnzPhDlgZQvpELHpy68sh1Zb/JSfLl6aEeC67zlRMSSstXdSYLNdSgz8070lIJeHVj3Q==",
				s);

		byte[] b2 = SignatureEncodingUtil.decode(s);

		Assert.assertArrayEquals(b, b2);
	}
}
