package com.github.joschi.jersey.security.smime;

import com.github.joschi.jersey.util.GenericType;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.operator.OperatorCreationException;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import javax.ws.rs.ext.Providers;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SignedInputImpl implements SignedInput {
    private PublicKey publicKey;
    private X509Certificate certificate;
    private Class type;
    private Type genericType;
    private MimeMultipart body;
    private Annotation[] annotations;
    private Providers providers;
    private Object entity;

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
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

    public MimeMultipart getBody() {
        return body;
    }

    public void setBody(MimeMultipart body) {
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
        return getEntity(type, genericType, annotations);
    }

    public Object getEntity(Class type) {
        return getEntity(type, null, annotations);
    }

    public Object getEntity(GenericType gt) {
        return getEntity(gt.getType(), gt.getGenericType(), annotations);
    }

    public Object getEntity(GenericType gt, Annotation[] ann) {
        return getEntity(gt.getType(), gt.getGenericType(), ann);
    }

    public Object getEntity(Class t, Type gt, Annotation[] ann) {
        if (entity != null) {
            return entity;
        }

        MimeBodyPart mbp;
        try {
            mbp = (MimeBodyPart) body.getBodyPart(0);
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
        entity = EnvelopedInputImpl.extractEntity(t, gt, ann, mbp, providers);
        return entity;
    }

    public boolean verify() throws Exception {
        if (certificate != null) {
            return verify(certificate);
        } else if (publicKey != null) {
            return verify(publicKey);
        } else {
            throw new IllegalStateException("Certificate nor public key properties set");
        }
    }

    public boolean verify(X509Certificate certificate) throws CMSException, MessagingException, OperatorCreationException {
        return verify(certificate.getPublicKey());
    }

    public boolean verify(PublicKey publicKey) throws CMSException, MessagingException, OperatorCreationException {
        SMIMESigned signed = new SMIMESigned(body);

        SignerInformationStore signers = signed.getSignerInfos();
        SignerInformation signer = (SignerInformation) signers.getSigners().iterator().next();

        JcaSimpleSignerInfoVerifierBuilder signerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();

        return signer.verify(signerInfoVerifierBuilder.build(publicKey));
    }


}
