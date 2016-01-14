package net.gini.jersey.security;

import net.gini.jersey.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

/**
 * Utility classes to extract PublicKey, PrivateKey, and X509Certificate from openssl generated PEM files
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public final class PemUtils {
    static {
        BouncyIntegration.init();
    }

    private PemUtils() {
    }

    public static X509Certificate decodeCertificate(InputStream is) throws IOException, CertificateException, NoSuchProviderException {
        byte[] der = pemToDer(is);
        ByteArrayInputStream bis = new ByteArrayInputStream(der);
        return DerUtils.decodeCertificate(bis);
    }

    /**
     * Extract a public key from a PEM string.
     */
    public static PublicKey decodePublicKey(String pem) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        byte[] der = pemToDer(pem);
        return DerUtils.decodePublicKey(der);
    }

    /**
     * Extract a private key that is a PKCS#8 PEM string (base64 encoded PKCS#8).
     */
    public static PrivateKey decodePrivateKey(String pem) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        byte[] der = pemToDer(pem);
        return DerUtils.decodePrivateKey(der);
    }

    public static PrivateKey decodePrivateKey(InputStream is) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        String pem = pemFromStream(is);
        return decodePrivateKey(pem);
    }

    /**
     * Decode a PEM file to DER format.
     */
    public static byte[] pemToDer(InputStream is) throws IOException {
        String pem = pemFromStream(is);
        return pemToDer(pem);
    }

    /**
     * Decode a PEM string to DER format.
     */
    public static byte[] pemToDer(String pem) throws IOException {
        return Base64.decode(removeBeginEnd(pem));
    }

    private static String removeBeginEnd(String pem) {
        return pem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)----", "")
                .replaceAll("\r\n", "\n")
                .trim();
    }

    public static String pemFromStream(InputStream is) throws IOException {
        DataInputStream dis = new DataInputStream(is);
        byte[] keyBytes = new byte[dis.available()];
        dis.readFully(keyBytes);
        dis.close();
        return new String(keyBytes, "UTF-8");
    }
}
