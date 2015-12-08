package com.github.joschi.jersey.security.smime;

import com.github.joschi.jersey.security.BouncyIntegration;
import com.github.joschi.jersey.util.Base64;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OutputEncryptor;

import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;
import javax.ws.rs.ext.Providers;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Provider
public class EnvelopedWriter implements MessageBodyWriter<EnvelopedOutput> {
    static {
        BouncyIntegration.init();
    }

    @Context
    private Providers providers;

    @Override
    public boolean isWriteable(Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
        return EnvelopedOutput.class.isAssignableFrom(type);
    }

    @Override
    public long getSize(EnvelopedOutput smimeOutput, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
        return -1;
    }

    @Override
    public void writeTo(EnvelopedOutput out, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType, MultivaluedMap<String, Object> headers, OutputStream os) throws IOException, WebApplicationException {
        try {
            headers.putSingle("Content-Disposition", "attachment; filename=\"smime.p7m\"");
            headers.putSingle("Content-Type", "application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"");
            headers.putSingle("Content-Transfer-Encoding", "base64");

            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
                    .setProvider("BC")
                    .build();
            if (out.getCertificate() == null) {
                throw new NullPointerException("The certificate object was not set.");
            }
            JceKeyTransRecipientInfoGenerator infoGenerator = new JceKeyTransRecipientInfoGenerator(out.getCertificate());
            infoGenerator.setProvider("BC");
            CMSEnvelopedDataStreamGenerator generator = new CMSEnvelopedDataStreamGenerator();
            generator.addRecipientInfoGenerator(infoGenerator);


            MimeBodyPart message = createBodyPart(providers, out);

            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final OutputStream encrypted = generator.open(baos, encryptor);

            message.writeTo(encrypted);
            encrypted.close();
            byte[] bytes = baos.toByteArray();
            String str = Base64.encodeBytes(bytes, Base64.DO_BREAK_LINES);
            os.write(str.getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static MimeBodyPart createBodyPart(Providers providers, SMIMEOutput out) throws IOException, MessagingException {
        ByteArrayOutputStream bodyOs = new ByteArrayOutputStream();
        MessageBodyWriter writer = providers.getMessageBodyWriter(out.getType(), out.getGenericType(), null, out.getMediaType());

        if (writer == null) {
            throw new RuntimeException("Failed to find writer for type: " + out.getType().getName());
        }

        MultivaluedMap<String, String> bodyHeaders = new MultivaluedHashMap<String, String>();
        bodyHeaders.add("Content-Type", out.getMediaType().toString());
        writer.writeTo(out.getEntity(), out.getType(), out.getGenericType(), null, out.getMediaType(), bodyHeaders, bodyOs);


        InternetHeaders ih = new InternetHeaders();

        for (Map.Entry<String, List<String>> entry : bodyHeaders.entrySet()) {
            for (String value : entry.getValue()) {
                ih.addHeader(entry.getKey(), value);
            }
        }
        return new MimeBodyPart(ih, bodyOs.toByteArray());
    }
}
