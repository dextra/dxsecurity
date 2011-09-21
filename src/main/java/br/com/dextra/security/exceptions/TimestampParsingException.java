package br.com.dextra.security.exceptions;

import java.text.MessageFormat;

public class TimestampParsingException extends SecurityException {

	private static final long serialVersionUID = 756539209070161878L;

	public TimestampParsingException(String timestamp, Throwable t) {
		super(MessageFormat.format("Error parsing timestamp : {0}", timestamp), t);
	}
}
