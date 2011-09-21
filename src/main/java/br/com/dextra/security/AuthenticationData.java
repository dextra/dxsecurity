package br.com.dextra.security;

import java.io.Serializable;
import java.text.MessageFormat;
import java.text.ParseException;
import java.util.Date;

import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import br.com.dextra.security.exceptions.TimestampParsingException;

public class AuthenticationData implements Serializable {

	private static final long serialVersionUID = 4913986898213824694L;

	protected static final DateTimeFormatter dateFormat = DateTimeFormat.forPattern("yyyyMMdd.HHmmssSSS");

	private String username;
	private Date timestamp;
	private String timestampAsString;
	private String provider;
	private transient String signature;
	private transient String token;

	public AuthenticationData(String username, String provider) {
		super();
		this.username = username;
		this.provider = provider;
		setTimestamp();
	}

	public AuthenticationData(String username, String provider, String timestamp, String signature, String token) throws ParseException {
		this.username = username;
		this.provider = provider;
		this.signature = signature;
		this.token = token;

		setTimestamp(parseDate(timestamp), timestamp);
	}

	protected Date parseDate(String timestamp) throws ParseException {
		try {
			return dateFormat.parseDateTime(timestamp).toDate();
		} catch (Exception e) {
			throw new TimestampParsingException(timestamp, e);
		}
	}

	protected void setTimestamp() {
		Date date = getToday();
		setTimestamp(date, dateFormat.print(date.getTime()));
	}

	protected Date getToday() {
		return new Date();
	}

	protected void setTimestamp(Date date, String timestamp) {
		this.timestamp = date;
		this.timestampAsString = timestamp;
	}

	public String getToken() {
		return token;
	}

	public String getSignature() {
		return signature;
	}

	public String getUsername() {
		return username;
	}

	public Date getTimestamp() {
		return timestamp;
	}

	public String getProvider() {
		return provider;
	}

	@Override
	public String toString() {
		return MessageFormat.format("{0}|{1}|{2}", username, provider, timestampAsString);
	}

	public String toStringFull() {
		return MessageFormat.format("{0}|{1}|{2}|{3}", username, provider, timestampAsString, signature);
	}

	public AuthenticationData renew() {
		return new AuthenticationData(this.getUsername(), this.getProvider());
	}

	public static AuthenticationData parse(String authToken) throws ParseException {
		String[] tokens = splitTokens(authToken);

		return new AuthenticationData(tokens[0], tokens[1], tokens[2], tokens[3], authToken);
	}

	public static String[] splitTokens(String authToken) {
		String[] tokens = authToken.split("\\|");

		return new String[] { tokens[0], tokens[1], tokens[2], fillTrailing(join(tokens, 3, tokens.length)) };
	}

	private static String fillTrailing(String token) {
		int trailingCharacters = token.length() % 4;

		StringBuilder sb = new StringBuilder(token);
		for (int i = 0; i < trailingCharacters; i++) {
			sb.append("=");
		}
		return sb.toString();
	}

	private static String join(String[] tokens, int start, int end) {
		StringBuilder sb = new StringBuilder();

		for (int i = start; i < end; i++) {
			sb.append(tokens[i]);
			if (i + 1 < end) {
				sb.append("|");
			}
		}

		return sb.toString();
	}

	public static String concatSignature(String authData, String signature) {
		return MessageFormat.format("{0}|{1}", authData, signature);
	}
}
