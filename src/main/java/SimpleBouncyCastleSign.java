import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Encoder;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class SimpleBouncyCastleSign {
    private static final String KEYSTORE_FILE = "keystore.p12";
    private static final String KEYSTORE_INSTANCE = "PKCS12";
    private static final String KEYSTORE_PWD = "123456";
    private static final String KEYSTORE_ALIAS = "Key1";

    public static void main(String[] args) {
        String message = "Hello world";
        String signed = sign(message);
        System.out.println(validate(signed));

    }

    private static String sign(String text) {
        Security.addProvider(new BouncyCastleProvider());

        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KEYSTORE_INSTANCE);
        } catch (KeyStoreException e) {
            System.out.print("Invalid Key Store instance " + KEYSTORE_FILE);
            e.printStackTrace();
        }

        if (ks == null) {
            System.out.print("Error getting Key Store instance " + KEYSTORE_FILE);
            return null;
        }

        try {
            ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PWD.toCharArray());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        Key key = null;
        try {
            key = ks.getKey(KEYSTORE_ALIAS, KEYSTORE_PWD.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        //Sign
        PrivateKey privKey = (PrivateKey) key;
        Signature signature = null;

        try {
            signature = Signature.getInstance("SHA1WithRSA", "BC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        if (signature == null) {
            System.out.print("Error creating signature factory");
            return null;
        }

        try {
            signature.initSign(privKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        try {
            signature.update(text.getBytes());
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        //Build CMS
        X509Certificate cert = null;
        try {
            cert = (X509Certificate) ks.getCertificate(KEYSTORE_ALIAS);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData msg = null;
        try {
            msg = new CMSProcessableByteArray(signature.sign());
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        certList.add(cert);
        Store certs = null;
        try {
            certs = new JcaCertStore(certList);
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = null;

        try {
            sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }

        try {
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        try {
            if (certs != null) {
                gen.addCertificates(certs);
            }
        } catch (CMSException e) {
            e.printStackTrace();
        }

        CMSSignedData sigData = null;
        try {
            if (msg != null) {
                sigData = gen.generate(msg, true);
            }
        } catch (CMSException e) {
            e.printStackTrace();
        }

        BASE64Encoder encoder = new BASE64Encoder();

        String envelopedData = null;
        try {
            if (sigData != null) {
                envelopedData = encoder.encode(sigData.getEncoded());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return envelopedData;
    }

    private static boolean validate(String envelopedData) {
        Security.addProvider(new BouncyCastleProvider());

        CMSSignedData cms = null;
        try {
            cms = new CMSSignedData(Base64.decode(envelopedData.getBytes()));
        } catch (CMSException e) {
            e.printStackTrace();
        }

        if (cms == null)
            return false;

        Store store = cms.getCertificates();
        SignerInformationStore signers = cms.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        for (SignerInformation aC : c) {
            Collection certCollection = store.getMatches(aC.getSID());
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate cert = null;
            try {
                cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
            } catch (CertificateException e) {
                e.printStackTrace();
            }
            try {
                if (aC.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                    return true;
                }
            } catch (CMSException e) {
                e.printStackTrace();
            } catch (OperatorCreationException e) {
                e.printStackTrace();
            }
        }
        return false;
    }
}
