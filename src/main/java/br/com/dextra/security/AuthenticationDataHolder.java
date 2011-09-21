package br.com.dextra.security;

public class AuthenticationDataHolder {

	private static ThreadLocal<AuthenticationData> holder = new ThreadLocal<AuthenticationData>();

	public static void register(AuthenticationData auth) {
		holder.set(auth);
	}

	public static void deregister() {
		holder.set(null);
	}

	public static AuthenticationData get() {
		return holder.get();
	}
}
