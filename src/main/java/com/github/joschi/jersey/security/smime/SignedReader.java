package com.github.joschi.jersey.security.smime;

import com.github.joschi.jersey.security.BouncyIntegration;
import com.github.joschi.jersey.util.Types;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import javax.ws.rs.Consumes;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.Provider;
import javax.ws.rs.ext.Providers;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Provider
@Consumes("*/*")
public class SignedReader implements MessageBodyReader<SignedInput> {
    static {
        BouncyIntegration.init();
    }

    @Context
    private Providers providers;

    @Override
    public boolean isReadable(Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
        return SignedInput.class.isAssignableFrom(type);
    }

    @Override
    public SignedInput readFrom(Class<SignedInput> type, Type genericType, Annotation[] annotations, MediaType mediaType, MultivaluedMap<String, String> headers, InputStream entityStream) throws IOException, WebApplicationException {
        Class<?> baseType = null;
        Type baseGenericType = null;

        if (genericType instanceof ParameterizedType) {
            ParameterizedType param = (ParameterizedType) genericType;
            baseGenericType = param.getActualTypeArguments()[0];
            baseType = Types.getRawType(baseGenericType);
        }
        try {
            ByteArrayDataSource ds = new ByteArrayDataSource(entityStream, mediaType.toString());
            MimeMultipart mm = new MimeMultipart(ds);
            SignedInputImpl input = new SignedInputImpl();
            input.setType(baseType);
            input.setGenericType(baseGenericType);
            input.setAnnotations(annotations);
            input.setBody(mm);
            input.setProviders(providers);
            return input;
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }

    }
}
