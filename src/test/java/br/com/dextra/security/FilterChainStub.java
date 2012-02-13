package br.com.dextra.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class FilterChainStub implements FilterChain {

	private boolean executed;

	@Override
	public void doFilter(ServletRequest arg0, ServletResponse arg1) throws IOException, ServletException {
		this.executed = true;
	}

	public boolean wasExecuted() {
		return executed;
	}
}
