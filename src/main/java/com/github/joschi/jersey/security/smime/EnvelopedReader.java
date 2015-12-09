package com.github.joschi.jersey.security.smime;

import com.github.joschi.jersey.security.BouncyIntegration;
import com.github.joschi.jersey.util.Types;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.ws.rs.Consumes;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.Provider;
import javax.ws.rs.ext.Providers;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Provider
@Consumes("*/*")
public class EnvelopedReader implements MessageBodyReader<EnvelopedInput> {
    static {
        BouncyIntegration.init();
    }

    private static final String CRLF = "\r\n";

    @Context
    private Providers providers;

    @Override
    public boolean isReadable(Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
        return EnvelopedInput.class.isAssignableFrom(type);
    }

    @Override
    public EnvelopedInput readFrom(Class<EnvelopedInput> type, Type genericType, Annotation[] annotations, MediaType mediaType, MultivaluedMap<String, String> headers, InputStream entityStream) throws
                                    IOException, WebApplicationException {
        Class<?> baseType = null;
        Type baseGenericType = null;

        if (genericType instanceof ParameterizedType) {
            ParameterizedType param = (ParameterizedType) genericType;
            baseGenericType = param.getActualTypeArguments()[0];
            baseType = Types.getRawType(baseGenericType);
        }
        EnvelopedInputImpl input = new EnvelopedInputImpl();
        input.setType(baseType);
        input.setGenericType(baseGenericType);

        StringBuilder headerString = new StringBuilder();
        if (headers.containsKey("Content-Disposition")) {
            headerString.append("Content-Disposition: ").append(headers.getFirst("Content-Disposition")).append(CRLF);
        }
        if (headers.containsKey("Content-Type")) {
            headerString.append("Content-Type: ").append(headers.getFirst("Content-Type")).append(CRLF);
        }
        if ("base64".equalsIgnoreCase(headers.getFirst("Content-Transfer-Encoding"))) {
            headerString.append("Content-Transfer-Encoding: ").append(headers.getFirst("Content-Transfer-Encoding")).append(CRLF);
        }
        headerString.append(CRLF);
        ByteArrayInputStream is = new ByteArrayInputStream(headerString.toString().getBytes("utf-8"));
        MimeBodyPart body;
        try {
            body = new MimeBodyPart(new SequenceInputStream(is, entityStream));
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
        input.setProviders(providers);
        input.setAnnotations(annotations);
        input.setBody(body);
        return input;
    }
}
