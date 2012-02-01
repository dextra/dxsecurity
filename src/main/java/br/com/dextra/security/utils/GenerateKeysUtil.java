package br.com.dextra.security.utils;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;

import br.com.dextra.security.Credential;
import br.com.dextra.security.configuration.StringBase64CertificateRepository;

public class GenerateKeysUtil {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        generateAndStoreKeys("/tmp");
    }

    public static void generateAndStoreKeys(String path) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();

        show("public.key", pair.getPublic().getEncoded());
        show("private.key", pair.getPrivate().getEncoded());

        store(pair.getPublic().getEncoded(), path + "/public.key");
        store(pair.getPrivate().getEncoded(), path + "/private.key");
        
        StringBase64CertificateRepository repo = new StringBase64CertificateRepository();
        repo.configurePrivateKey(new String(Base64.encodeBase64(pair.getPrivate().getEncoded())));
        repo.configurePublicKey("Test", new String(Base64.encodeBase64(pair.getPublic().getEncoded())));

        Credential credential = new Credential("user", "Test");
		String signature = AuthenticationUtil.sign(credential, repo);
		System.out.println(Credential.concatSignature(credential.toString(), signature));
    }

    private static void show(String s, byte[] encoded) {
        byte[] base64 = Base64.encodeBase64(encoded);

        System.out.println(s);
        System.out.println(new String(base64));
        System.out.println();
    }

    private static void store(byte[] encoded, String path) throws IOException {
        FileOutputStream fos = new FileOutputStream(path);
        BufferedOutputStream bos = new BufferedOutputStream(fos);

        bos.write(encoded);

        bos.close();
        fos.close();
    }
}
