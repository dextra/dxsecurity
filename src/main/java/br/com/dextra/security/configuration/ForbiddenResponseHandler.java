package br.com.dextra.security.configuration;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ForbiddenResponseHandler implements ResponseHandler {

	public static final int HTTP_ERROR_CODE = 403;

	@Override
	public void sendResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.sendError(HTTP_ERROR_CODE);
	}
}
