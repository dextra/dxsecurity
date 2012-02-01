package br.com.dextra.security;

public class CredentialHolder {

	private static ThreadLocal<Credential> holder = new ThreadLocal<Credential>();

	public static void register(Credential auth) {
		holder.set(auth);
	}

	public static void deregister() {
		holder.set(null);
	}

	public static Credential get() {
		return holder.get();
	}
}
