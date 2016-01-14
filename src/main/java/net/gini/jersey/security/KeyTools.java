package net.gini.jersey.security;


import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public final class KeyTools {
    static {
        BouncyIntegration.init();
    }

    private KeyTools() {
    }

    public static X509Certificate generateTestCertificate(KeyPair pair) throws CertificateException, OperatorCreationException {
        final X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name cn = nameBuilder.addRDN(BCStyle.CN, "Test Certificate").build();

        final byte[] encoded = pair.getPublic().getEncoded();
        final SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));

        final X509v1CertificateBuilder certBuilder = new X509v1CertificateBuilder(
                cn,
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() - 10000),
                new Date(System.currentTimeMillis() + 10000),
                cn,
                subjectPublicKeyInfo
        );

        final JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        final ContentSigner contentSigner = contentSignerBuilder.build(pair.getPrivate());
        final X509CertificateHolder certificateHolder = certBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate(certificateHolder);
    }
}
