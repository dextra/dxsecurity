package br.com.dextra.security.configuration;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import br.com.dextra.security.CredentialHolder;

public class WriteTokenOnResponseResponseHandler implements ResponseHandler {

	@Override
	public void sendResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.getWriter().append(CredentialHolder.get().toStringFull());
	}
}
