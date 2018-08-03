import com.sun.xml.internal.messaging.saaj.soap.SOAPDocument;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import util.KeyStorage;
import util.SOAPBuilderConfig;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.*;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

public class SignImpl implements Sign {

    private KeyStorage keyStorage;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    SignImpl(KeyStorage storage){
        keyStorage = storage;
    }

    private KeyStore loadKeyStore() {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(keyStorage.getType());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            assert ks != null;
            ks.load(new FileInputStream(keyStorage.getLocation()), keyStorage.getPassword().toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ks;
    }

    private PrivateKey getPrivateKey() {
        KeyStore ks = loadKeyStore();
        try {
            assert ks != null;
            return (PrivateKey) ks.getKey(ks.aliases().nextElement(), keyStorage.getPassword().toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private X509Certificate getCertificate() {
        KeyStore ks = loadKeyStore();
        try {
            assert ks != null;
            return X509Certificate.getInstance(ks.getCertificate(ks.aliases().nextElement()).getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public SOAPMessage sign(final Serializable value) {
        return sign(value, new SOAPBuilderConfig());
    }

    public SOAPMessage sign(final Serializable value, SOAPBuilderConfig config) {
        try {
            SOAPBuilder soapBuilder = SOAPBuilderFactory.newInstance(getPrivateKey(), UUID.randomUUID().toString(), getCertificate(),config);
            Document document = soapBuilder.createDocument(value);
            SOAPMessage message = soapBuilder.createSoapMessage(document);
            XMLSignature signature = soapBuilder.createSignature(message);
            DOMSignContext sigContext = soapBuilder.createSignContext(message);
            signature.sign(sigContext);
            return message;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
