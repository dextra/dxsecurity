package br.com.dextra.security;

import java.io.Serializable;
import java.text.MessageFormat;
import java.util.Date;

import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import br.com.dextra.security.exceptions.TimestampParsingException;

public class Credential implements Serializable {

	private static final long serialVersionUID = 4913986898213824694L;

	protected static final DateTimeFormatter dateFormat = DateTimeFormat.forPattern("yyyyMMdd.HHmmssSSS");

	private String username;
	private String provider;
	private Date timestamp;
	private String timestampAsString;

	private transient String signature;
	private transient String token;

	public Credential(String username, String provider) {
		super();
		this.username = username;
		this.provider = provider;
		setTimestamp();
	}

	public Credential(String username, String provider, String timestamp, String signature, String token) {
		this.username = username;
		this.provider = provider;
		this.signature = signature;
		this.token = token;

		setTimestamp(parseDate(timestamp), timestamp);
	}

	protected Date parseDate(String timestamp) {
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

	protected void setSignature(String signature) {
		this.signature = signature;
	}

	@Override
	public String toString() {
		return MessageFormat.format("{0}|{1}|{2}", username, provider, timestampAsString);
	}

	public String toStringFull() {
		return MessageFormat.format("{0}|{1}|{2}|{3}", username, provider, timestampAsString, signature);
	}

	public Credential renew() {
		return new Credential(this.getUsername(), this.getProvider());
	}

	public static Credential parse(String token) {
		String[] tokens = splitTokens(token);

		return new Credential(tokens[0], tokens[1], tokens[2], tokens[3], token);
	}

	public static String[] splitTokens(String token) {
		String[] tokens = token.split("\\|");

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

	public static String concatSignature(String token, String signature) {
		return MessageFormat.format("{0}|{1}", token, signature);
	}
}
