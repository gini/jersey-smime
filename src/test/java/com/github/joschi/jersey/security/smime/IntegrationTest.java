package com.github.joschi.jersey.security.smime;

import com.github.joschi.jersey.security.KeyTools;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.test.framework.JerseyTest;
import com.sun.jersey.test.framework.spi.container.TestContainerException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class IntegrationTest extends JerseyTest {
    @Path("/smime/encrypted")
    public static class EncryptedResource {
        @GET
        public EnvelopedOutput get() {
            EnvelopedOutput output = new EnvelopedOutput("hello world", "text/plain");
            output.setCertificate(cert);
            return output;
        }

        @POST
        public void post(EnvelopedInput<String> input) {
            String str = input.getEntity(privateKey, cert);
            Assert.assertEquals("input", str);
        }
    }

    @Path("/smime/signed")
    public static class SignedResource {
        @GET
        public SignedOutput get() {
            SignedOutput output = new SignedOutput("hello world", "text/plain");
            output.setCertificate(cert);
            output.setPrivateKey(privateKey);
            return output;
        }

        @POST
        public void post(SignedInput<String> input) throws Exception {
            String str = input.getEntity();
            Assert.assertEquals("input", str);
            Assert.assertTrue(input.verify(cert));
        }
    }

    @Path("/smime/encrypted/signed")
    public static class EncryptedSignedResource {
        @GET
        public EnvelopedOutput get() {
            SignedOutput signed = new SignedOutput("hello world", "text/plain");
            signed.setCertificate(cert);
            signed.setPrivateKey(privateKey);

            EnvelopedOutput output = new EnvelopedOutput(signed, "multipart/signed");
            output.setCertificate(cert);
            return output;
        }

        @POST
        public void post(EnvelopedInput<SignedInput<String>> input) throws Exception {
            SignedInput<String> str = input.getEntity(privateKey, cert);
            Assert.assertEquals("input", str.getEntity());
            Assert.assertTrue(str.verify(cert));
        }
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static X509Certificate cert;
    private static PrivateKey privateKey;

    public IntegrationTest() throws TestContainerException {
        super("com.github.joschi.jersey.security.smime");
    }

    @BeforeClass
    public static void setup() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        privateKey = keyPair.getPrivate();
        cert = KeyTools.generateTestCertificate(keyPair);
    }

    @Test
    public void testSignedOutput() throws Exception {
        ClientResponse res = resource().path("/smime/signed").get(ClientResponse.class);
        Assert.assertEquals(200, res.getStatus());
        System.out.println(res.getEntity(String.class));
        MediaType contentType = MediaType.valueOf(res.getHeaders().getFirst("Content-Type"));
        System.out.println(contentType);
    }

    @Test
    public void testSignedOutput2() throws Exception {
        /*ClientRequest request = new ClientRequest(TestPortProvider.generateURL("/smime/signed"));
        SignedInput signed = request.getTarget(SignedInput.class);
        String output = (String) signed.getEntity(String.class);
        System.out.println(output);
        Assert.assertEquals("hello world", output);
        Assert.assertTrue(signed.verify(cert));*/
    }

    @Test
    public void testEncryptedOutput() throws Exception {
        ClientResponse res = resource().path("/smime/encrypted").get(ClientResponse.class);
        Assert.assertEquals(200, res.getStatus());
        System.out.println(res.getEntity(String.class));
        MediaType contentType = MediaType.valueOf(res.getHeaders().getFirst("Content-Type"));
        System.out.println(contentType);
    }

    @Test
    public void testEncryptedOutput2() throws Exception {
        /*ClientRequest request = new ClientRequest(TestPortProvider.generateURL("/smime/encrypted"));
        EnvelopedInput enveloped = request.getTarget(EnvelopedInput.class);
        String output = (String) enveloped.getEntity(String.class, privateKey, cert);
        System.out.println(output);
        Assert.assertEquals("hello world", output);*/
    }

    @Test
    public void testEncryptedSignedOutputToFile() throws Exception {
        ClientResponse res = resource().path("/smime/encrypted/signed").get(ClientResponse.class);
        MediaType contentType = MediaType.valueOf(res.getHeaders().getFirst("Content-Type"));
        System.out.println(contentType);
        System.out.println();
        System.out.println(res.getEntity(String.class));

        FileOutputStream os = new FileOutputStream("python_encrypted_signed.txt");
        os.write("Content-Type: ".getBytes());
        os.write(contentType.toString().getBytes());
        os.write("\r\n".getBytes());
        os.write(res.getEntity(String.class).getBytes());
        os.close();
    }

    @Test
    public void testEncryptedSignedOutput() throws Exception {
        /*ClientRequest request = new ClientRequest(TestPortProvider.generateURL("/smime/encrypted/signed"));
        EnvelopedInput enveloped = request.getTarget(EnvelopedInput.class);
        SignedInput signed = (SignedInput) enveloped.getEntity(SignedInput.class, privateKey, cert);
        String output = (String) signed.getEntity(String.class);
        System.out.println(output);
        Assert.assertEquals("hello world", output);
        Assert.assertTrue(signed.verify(cert));
        Assert.assertEquals("hello world", output);*/
    }

    @Test
    public void testEncryptedInput() throws Exception {
        EnvelopedOutput output = new EnvelopedOutput("input", "text/plain");
        output.setCertificate(cert);
        ClientResponse res = resource()
                        .path("/smime/encrypted")
                        .accept("*/*")
                        .post(ClientResponse.class, output);
        Assert.assertEquals(204, res.getStatus());
    }

    @Test
    public void testEncryptedSignedInput() throws Exception {
        SignedOutput signed = new SignedOutput("input", "text/plain");
        signed.setPrivateKey(privateKey);
        signed.setCertificate(cert);
        EnvelopedOutput output = new EnvelopedOutput(signed, "multipart/signed");
        output.setCertificate(cert);
        ClientResponse res = resource()
                .path("/smime/encrypted/signed")
                .accept("*/*")
                .post(ClientResponse.class, output);
        Assert.assertEquals(204, res.getStatus());
    }

    @Test
    public void testSignedInput() throws Exception {
        SignedOutput output = new SignedOutput("input", "text/plain");
        output.setCertificate(cert);
        output.setPrivateKey(privateKey);
        ClientResponse res = resource()
                        .path("/smime/signed")
                        .accept("*/*")
                        .post(ClientResponse.class, output);
        Assert.assertEquals(204, res.getStatus());
    }
}
