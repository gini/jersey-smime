package com.github.joschi.jersey.security.smime;

import com.github.joschi.jersey.util.Base64;
import com.github.joschi.jersey.util.GenericType;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEUtil;

import javax.mail.Header;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.Providers;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class EnvelopedInputImpl implements EnvelopedInput {
    private PrivateKey privateKey;
    private X509Certificate certificate;
    private Class type;
    private Type genericType;
    private MimeBodyPart body;
    private Annotation[] annotations;
    private Providers providers;

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public Class getType() {
        return type;
    }

    public void setType(Class type) {
        this.type = type;
    }

    public void setType(GenericType type) {
        this.type = type.getType();
        this.genericType = type.getGenericType();
    }

    public Type getGenericType() {
        return genericType;
    }

    public void setGenericType(Type genericType) {
        this.genericType = genericType;
    }

    public MimeBodyPart getBody() {
        return body;
    }

    public void setBody(MimeBodyPart body) {
        this.body = body;
    }

    public Annotation[] getAnnotations() {
        return annotations.clone();
    }

    public void setAnnotations(Annotation[] annotations) {
        this.annotations = annotations.clone();
    }

    public Providers getProviders() {
        return providers;
    }

    public void setProviders(Providers providers) {
        this.providers = providers;
    }

    public Object getEntity() {
        return getEntity(type, genericType, annotations, privateKey, certificate);
    }

    public Object getEntity(PrivateKey pKey, X509Certificate cert) {
        return getEntity(type, genericType, annotations, pKey, cert);
    }

    public Object getEntity(Class type) {
        return getEntity(type, null, annotations, privateKey, certificate);
    }

    public Object getEntity(Class type, PrivateKey key, X509Certificate cert) {
        return getEntity(type, null, annotations, key, cert);
    }

    public Object getEntity(GenericType type) {
        return getEntity(type.getType(), type.getGenericType(), annotations, privateKey, certificate);
    }

    public Object getEntity(GenericType type, PrivateKey key, X509Certificate cert) {
        return getEntity(type, annotations, key, cert);
    }

    public Object getEntity(GenericType gt, Annotation[] ann, PrivateKey pKey, X509Certificate cert) {
        return getEntity(gt.getType(), gt.getGenericType(), ann, pKey, cert);
    }

    public Object getEntity(Class t, Type gt, Annotation[] ann, PrivateKey pKey, X509Certificate cert) {
        final MimeBodyPart decrypted;

        try {
            MimeBodyPart encryptedBodyPartBase64 = body;
            SMIMEEnveloped m = new SMIMEEnveloped(encryptedBodyPartBase64);
            JceKeyTransRecipientId recId = new JceKeyTransRecipientId(cert);

            RecipientInformationStore recipients = m.getRecipientInfos();
            RecipientInformation recipientInfo = recipients.get(recId);
            Recipient recipient = new JceKeyTransEnvelopedRecipient(pKey).setProvider("BC");

            decrypted = SMIMEUtil.toMimeBodyPart(recipientInfo.getContent(recipient));
        } catch (Exception e1) {
            throw new RuntimeException(e1);
        }

        return extractEntity(t, gt, ann, decrypted, providers);
    }

    public static <T> Object extractEntity(Class<T> t, Type gt, Annotation[] ann, MimeBodyPart decrypted, Providers providers) {
        MultivaluedMap<String, String> mimeHeaders = new MultivaluedHashMap<String, String>();
        final Enumeration e;
        try {
            e = decrypted.getAllHeaders();
        } catch (MessagingException e1) {
            throw new RuntimeException(e1);
        }
        while (e.hasMoreElements()) {
            Header header = (Header) e.nextElement();
            mimeHeaders.add(header.getName(), header.getValue());
        }
        String contentType = "text/plain";
        if (mimeHeaders.containsKey("Content-Type")) {
            contentType = mimeHeaders.getFirst("Content-Type");
        }
        MediaType mediaType = MediaType.valueOf(contentType);
        MessageBodyReader<T> reader = providers.getMessageBodyReader(t, gt, ann, mediaType);
        if (reader == null) {
            throw new RuntimeException("Could not find a message body reader for type: " + t.getClass().getName());
        }
        try {
            InputStream inputStream = decrypted.getInputStream();
            return reader.readFrom(t, gt, ann, mediaType, mimeHeaders, inputStream);
        } catch (Exception e1) {
            throw new RuntimeException(e1);
        }
    }


}
