package com.github.joschi.jersey.security.smime;

import com.github.joschi.jersey.security.PemUtils;
import com.github.joschi.jersey.util.Base64;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.OutputEncryptor;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class EnvelopedTest {

    private static String python_smime = "MIIBagYJKoZIhvcNAQcDoIIBWzCCAVcCAQAxgewwgekCAQAwUjBFMQswCQYDVQQG\n" +
            "EwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lk\n" +
            "Z2l0cyBQdHkgTHRkAgkA7oW81OriflAwDQYJKoZIhvcNAQEBBQAEgYA1AWIoRMsb\n" +
            "Gv2DsHLjcvu6URZPqS0atjGW7uqlthmoQ4XB+l0y+iy2rXFuJnz+iLp/EIn92UpR\n" +
            "ZeFHPoQEDklkk5QqRaIBvkZiJgiPs9VuWiXVfHeOei9Oneyfja9Q88eFWHFToWok\n" +
            "LIDie+Wt/mMYY23QSVTY3r+cgTnOyV8gyDBjBgkqhkiG9w0BBwEwFAYIKoZIhvcN\n" +
            "AwcECJYFaD/eHDkHgEDIBLBzczEdLLk7nQzORmVist6gv30Ez9LCzHlnFteU+jVr\n" +
            "zAUGo6VoZZMmyLVeYEZoXqEjY6fN+rpSWoUVtNQM";
    private static X509Certificate cert;
    private static PrivateKey privateKey;

    @BeforeClass
    public static void setup() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
      /*
      InputStream certIs = Thread.currentThread().getContextClassLoader().getResourceAsStream("mycert.der");
      cert = PemUtils.getCertificateFromDer(certIs);
      */

        InputStream certIs = Thread.currentThread().getContextClassLoader().getResourceAsStream("mycert.pem");
        cert = PemUtils.decodeCertificate(certIs);
      /*
      InputStream privateIs = Thread.currentThread().getContextClassLoader().getResourceAsStream("mycert-private.der");
      privateKey = PemUtils.getPrivateFromDer(privateIs);
      */
        InputStream privateIs = Thread.currentThread().getContextClassLoader().getResourceAsStream("mycert-private.pem");
        privateKey = PemUtils.decodePrivateKey(privateIs);
    }

    @Test
    public void testBody() throws Exception {
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
                .setProvider("BC")
                .build();
        JceKeyTransRecipientInfoGenerator infoGenerator = new JceKeyTransRecipientInfoGenerator(cert);
        CMSEnvelopedDataStreamGenerator generator = new CMSEnvelopedDataStreamGenerator();
        generator.addRecipientInfoGenerator(infoGenerator);


        InternetHeaders ih = new InternetHeaders();
        ih.addHeader("Content-Type", "application/xml");

        MimeBodyPart _msg = new MimeBodyPart(ih, "<customer name=\"bill\"/>".getBytes());

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        OutputStream encrypted = generator.open(os, encryptor);

        _msg.writeTo(encrypted);
        encrypted.close();

        byte[] base64 = Base64.encodeBytesToBytes(os.toByteArray());

        ih = new InternetHeaders();
        ih.addHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
        ih.addHeader("Content-Type", "application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"");
        ih.addHeader("Content-Transfer-Encoding", "base64");
        MimeBodyPart mp = new MimeBodyPart(ih, base64);

        // output this to smime.txt for decrypt_smime.py
        //outputFile(mp);

        mp = decode2Mime(mp);

        Assert.assertEquals("application/xml", mp.getContentType());

        String body = toString(mp.getInputStream());
        Assert.assertEquals("<customer name=\"bill\"/>", body.trim());
    }

    @Test
    public void testHeaders()
            throws Exception {
        InternetHeaders ih = new InternetHeaders();
        ih.addHeader("Content-Type", "application/xml");

        MimeBodyPart _msg = new MimeBodyPart(ih, "<customer name=\"bill\"/>".getBytes());


        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
                .setProvider("BC")
                .build();

        RecipientInfoGenerator generator = new JceKeyTransRecipientInfoGenerator(cert);
        gen.addRecipientInfoGenerator(generator);

        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart mp = gen.generate(_msg, encryptor);

        output(mp);
    }

    private void output(MimeBodyPart mp) throws IOException, MessagingException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        mp.writeTo(os);
        String s = new String(os.toByteArray());
        System.out.println(s);
    }

    private void outputFile(MimeBodyPart mp) throws IOException, MessagingException {
        FileOutputStream os = new FileOutputStream("smime.txt");
        mp.writeTo(os);
        os.close();
    }

    @Test
    public void testFromPythonGenerated() throws Exception {
        InternetHeaders ih = new InternetHeaders();
        ih.addHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
        ih.addHeader("Content-Type", "application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"");
        ih.addHeader("Content-Transfer-Encoding", "base64");
        MimeBodyPart mp = new MimeBodyPart(ih, python_smime.getBytes());

        output(mp);
        System.out.println("------------");
        mp = decode2Mime(mp);

        Assert.assertEquals("application/xml", mp.getContentType());

        String body = toString(mp.getInputStream());
        Assert.assertEquals("<customer name=\"bill\"/>", body.trim());


    }

    @Test
    public void testFromPythonGenerated2() throws Exception {
        ByteArrayInputStream is = new ByteArrayInputStream(python_smime.getBytes("utf-8"));
        MimeBodyPart mp = decode2Mime(is);

        Assert.assertEquals("application/xml", mp.getContentType());

        String body = toString(mp.getInputStream());
        Assert.assertEquals("<customer name=\"bill\"/>", body.trim());


    }

    private static String toString(InputStream is) throws Exception {
        DataInputStream dis = new DataInputStream(is);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        dis.close();
        return new String(bytes);

    }

    private MimeBodyPart decode2Mime(InputStream body) throws MessagingException, CMSException, SMIMEException, IOException {
        StringBuilder builder = new StringBuilder();
        builder.append("Content-Disposition: attachment; filename=\"smime.p7m\"\r\n");
        builder.append("Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\n");
        builder.append("Content-Transfer-Encoding: base64\r\n\r\n");
        ByteArrayInputStream is = new ByteArrayInputStream(builder.toString().getBytes("utf-8"));
        MimeBodyPart mp = new MimeBodyPart(new SequenceInputStream(is, body));
        return decode2Mime(mp);
    }

    private MimeBodyPart decode2Mime(MimeBodyPart mp) throws MessagingException, CMSException, SMIMEException {
        final Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);
        final RecipientId recipientId = new JceKeyTransRecipientId(cert);

        final SMIMEEnveloped m = new SMIMEEnveloped(mp);
        final RecipientInformationStore recipients = m.getRecipientInfos();
        final RecipientInformation recipientInformation = recipients.get(recipientId);

        return SMIMEUtil.toMimeBodyPart(recipientInformation.getContent(recipient));
    }


}
