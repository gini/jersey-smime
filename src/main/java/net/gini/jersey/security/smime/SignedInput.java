package net.gini.jersey.security.smime;

import net.gini.jersey.util.GenericType;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface SignedInput<T> {
    T getEntity();

    <T2> T2 getEntity(Class<T2> type);

    Object getEntity(GenericType type);

    boolean verify() throws Exception;

    boolean verify(X509Certificate certificate) throws Exception;

    boolean verify(PublicKey publicKey) throws Exception;
}
