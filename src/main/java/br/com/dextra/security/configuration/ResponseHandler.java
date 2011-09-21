package br.com.dextra.security.configuration;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface ResponseHandler {

	void sendResponse(HttpServletRequest request, HttpServletResponse response) throws IOException;
}
