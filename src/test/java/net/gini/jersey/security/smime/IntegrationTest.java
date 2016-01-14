package net.gini.jersey.security.smime;

import net.gini.jersey.security.KeyTools;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.filter.LoggingFilter;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.jdkhttp.JdkHttpServerTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

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

    public IntegrationTest() {

    }

    @Override
    protected Application configure() {
        final ResourceConfig config = new ResourceConfig();
        config.packages("com.github.joschi.jersey.security.smime");
        config.register(EnvelopedWriter.class);
        config.register(SignedWriter.class);
        config.register(EnvelopedReader.class);
        config.register(SignedReader.class);
        config.register(LoggingFilter.class);
        return config;
    }

    @Override
    public TestContainerFactory getTestContainerFactory() {
        //InMemoryTestContainerFactory would fail due to a bug which does not set headers correctly
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true"); //Otherwise Content-Transfer-Encoding is erased
        return new JdkHttpServerTestContainerFactory();
    }

    @Override
    protected void configureClient(final ClientConfig config) {
        config.register(EnvelopedWriter.class);
        config.register(SignedWriter.class);
        config.register(EnvelopedReader.class);
        config.register(SignedReader.class);
        config.register(LoggingFilter.class);
    }

    @BeforeClass
    public static void setup() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        privateKey = keyPair.getPrivate();
        cert = KeyTools.generateTestCertificate(keyPair);
    }

    @Test
    public void testSignedOutput() throws Exception {
        Response res = target("/smime/signed").request().get();
        Assert.assertEquals(200, res.getStatus());
        final String entity = res.readEntity(String.class);
        MediaType contentType = MediaType.valueOf(res.getHeaders().getFirst("Content-Type").toString());
        Assert.assertTrue(contentType.toString().startsWith("multipart/signed"));
        System.out.println(entity);
        System.out.println(contentType);
    }

    @Test
    public void testSignedOutput2() throws Exception {
        Response response = target("/smime/signed").request().get();
        SignedInput signed = response.readEntity(SignedInput.class);
        String output = (String) signed.getEntity(String.class);
        System.out.println(output);
        Assert.assertEquals("hello world", output);
        Assert.assertTrue(signed.verify(cert));
    }

    @Test
    public void testEncryptedOutput() throws Exception {
        Response res = target("/smime/encrypted").request().get();
        Assert.assertEquals(200, res.getStatus());
        System.out.println(res.readEntity(String.class));
        MediaType contentType = MediaType.valueOf(res.getHeaders().getFirst("Content-Type").toString());
        System.out.println(contentType);
    }

    @Test
    public void testEncryptedOutput2() throws Exception {
        Response response = target("/smime/encrypted").request().get();
        EnvelopedInput enveloped = response.readEntity(EnvelopedInput.class);
        String output = (String) enveloped.getEntity(String.class, privateKey, cert);
        System.out.println(output);
        Assert.assertEquals("hello world", output);
    }

    @Test
    public void testEncryptedSignedOutputToFile() throws Exception {
        Response res = target("/smime/encrypted/signed").request().get();
        MediaType contentType = MediaType.valueOf(res.getHeaders().getFirst("Content-Type").toString());
        System.out.println(contentType);
        System.out.println();
        String entity = res.readEntity(String.class);
        System.out.println(entity);

        FileOutputStream os = new FileOutputStream("python_encrypted_signed.txt");
        os.write("Content-Type: ".getBytes());
        os.write(contentType.toString().getBytes());
        os.write("\r\n".getBytes());
        os.write(entity.getBytes());
        os.close();
    }

    @Test
    public void testEncryptedSignedOutput() throws Exception {
        Response response = target("/smime/encrypted/signed").request().get();
        EnvelopedInput enveloped = response.readEntity(EnvelopedInput.class);
        SignedInput signed = (SignedInput) enveloped.getEntity(SignedInput.class, privateKey, cert);
        String output = (String) signed.getEntity(String.class);
        System.out.println(output);
        Assert.assertEquals("hello world", output);
        Assert.assertTrue(signed.verify(cert));
        Assert.assertEquals("hello world", output);
    }

    @Test
    public void testEncryptedInput() throws Exception {
        EnvelopedOutput output = new EnvelopedOutput("input", "text/plain");
        output.setCertificate(cert);

        Response res = target("/smime/encrypted").request()
                .post(Entity.entity(output, MediaType.WILDCARD));
        Assert.assertEquals(204, res.getStatus());
    }

    @Test
    public void testEncryptedSignedInput() throws Exception {
        SignedOutput signed = new SignedOutput("input", "text/plain");
        signed.setPrivateKey(privateKey);
        signed.setCertificate(cert);
        EnvelopedOutput output = new EnvelopedOutput(signed, "multipart/signed");
        output.setCertificate(cert);
        Response res = target("/smime/encrypted/signed").request()
                .accept("*/*")
                .post(Entity.entity(output, MediaType.WILDCARD_TYPE));
        Assert.assertEquals(204, res.getStatus());
    }

    @Test
    public void testSignedInput() throws Exception {
        SignedOutput output = new SignedOutput("input", "text/plain");
        output.setCertificate(cert);
        output.setPrivateKey(privateKey);
        Response res = target("/smime/signed").request()
                .accept("*/*")
                .post(Entity.entity(output, MediaType.WILDCARD_TYPE));
        Assert.assertEquals(204, res.getStatus());
    }
}
