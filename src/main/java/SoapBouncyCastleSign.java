
import model.User;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
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
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

public abstract class SoapBouncyCastleSign {
    private static final DocumentBuilderFactory DOCUMENT_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();

    private static final XMLSignatureFactory XML_SIGNATURE_FACTORY = XMLSignatureFactory.getInstance("DOM");

    private static final XPathFactory X_PATH_FACTORY = XPathFactory.newInstance();

    private static final String NS_WSSECURITY = "http://schemas.xmlsoap.org/soap/security/2000-12";

    private static final String PREFIX_WSSECURITY = "ds";

    private static final String SIGNATURE_ID = "id";

    private static final String SECURUTY = "Security";

    private static final String SECURITY_PREFFIX = "wsse";

    private static final String SECURITY_NAMESPACE_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

    static {
        Security.addProvider(new BouncyCastleProvider());

        DOCUMENT_BUILDER_FACTORY.setNamespaceAware(Boolean.TRUE);
    }

    private Marshaller getMarshaller(Class... clazz) throws JAXBException {
        JAXBContext jaxbContext = JAXBContext.newInstance(clazz);

        return jaxbContext.createMarshaller();
    }

    protected abstract Serializable createRequest();

    private Node marshall(Serializable request, Marshaller marshaller) throws ParserConfigurationException, JAXBException {
        DOMResult domResult = new DOMResult();

        marshaller.marshal(request, domResult);

        return domResult.getNode().getFirstChild();
    }

    private SOAPMessage sign(Node request) throws SOAPException, ParserConfigurationException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyException, MarshalException, XMLSignatureException, XPathExpressionException, CertificateException, NoSuchProviderException, KeyStoreException, IOException, java.security.cert.CertificateException, UnrecoverableKeyException {
        Security.addProvider(new BouncyCastleProvider());

        String bodyId = UUID.randomUUID().toString();

        //создание документа с объектом внутри
        Document document = DOCUMENT_BUILDER_FACTORY
                .newDocumentBuilder()
                .newDocument();

        document.appendChild(document.importNode(request, true));

        SOAPMessage soapMessage = MessageFactory
                .newInstance()
                .createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        SOAPEnvelope soapEnvelope = soapPart.getEnvelope();

        SOAPBody soapBody = soapEnvelope.getBody();
        soapBody.addDocument(document);

        soapBody.addAttribute(
                soapEnvelope.createName(
                        SIGNATURE_ID,
                        PREFIX_WSSECURITY,
                        NS_WSSECURITY
                ),
                bodyId
        );

        soapEnvelope.getHeader().addHeaderElement(
                soapEnvelope.createName(
                        SECURUTY,
                        SECURITY_PREFFIX,
                        SECURITY_NAMESPACE_URI
                )
        ).setMustUnderstand(Boolean.TRUE);

        Source source = soapPart.getContent();
        Node root = ((DOMSource) source).getNode();

        Reference reference = XML_SIGNATURE_FACTORY.newReference("#" + bodyId,
                XML_SIGNATURE_FACTORY.newDigestMethod(DigestMethod.SHA1, null));
        SignedInfo signedInfo = XML_SIGNATURE_FACTORY.newSignedInfo(
                XML_SIGNATURE_FACTORY.newCanonicalizationMethod(
                        CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                        (C14NMethodParameterSpec) null),
                XML_SIGNATURE_FACTORY.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                Collections.singletonList(reference)
        );
        KeyInfoFactory keyInfoFactory = XML_SIGNATURE_FACTORY.getKeyInfoFactory();

        KeyValue keyValue = keyInfoFactory.newKeyValue(getCertificate().getPublicKey());

        X509IssuerSerial x509IssuerSerial = keyInfoFactory.newX509IssuerSerial(
                getCertificate().getIssuerDN().getName(),
                new BigInteger("1"));

        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Arrays.asList(keyValue, x509IssuerSerial));

        XMLSignature sig = XML_SIGNATURE_FACTORY.newXMLSignature(signedInfo, keyInfo);

        Element security = getSecurityElementFrom(root);
        Element body = getBodyElementFrom(root);
        DOMSignContext sigContext = new DOMSignContext(getPrivateKey(), security);
        sigContext.putNamespacePrefix(XMLSignature.XMLNS, PREFIX_WSSECURITY);
        sigContext.setIdAttributeNS(body, NS_WSSECURITY, SIGNATURE_ID);
        sig.sign(sigContext);

        return soapMessage;
    }

    private Element getBodyElementFrom(Node payload) throws XPathExpressionException {
        XPath xPath = X_PATH_FACTORY.newXPath();

        return (Element) xPath.evaluate("//*[local-name()='Envelope']/*[local-name()='Body']", payload, XPathConstants.NODE);
    }

    private Element getSecurityElementFrom(Node payload) throws XPathExpressionException {
        XPath xPath = X_PATH_FACTORY.newXPath();

        return (Element) xPath.evaluate("/*[local-name()='Envelope']/*[local-name()='Header']/*[local-name()='Security']", payload, XPathConstants.NODE);
    }

    public static void main(String[] args) throws XPathExpressionException, KeyException, XMLSignatureException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException, MarshalException, ParserConfigurationException, InvalidAlgorithmParameterException, JAXBException, IOException, NoSuchProviderException, java.security.cert.CertificateException, SOAPException {
        SoapBouncyCastleSign sign = new SoapBouncyCastleSign() {
            @Override
            protected Serializable createRequest() {
                User user = new User();
                user.setId(1);
                user.setName("User");
                return user;
            }
        };
        sign.signRequest();
    }

    public void signRequest() throws JAXBException, ParserConfigurationException, CertificateException, KeyException, MarshalException, NoSuchAlgorithmException, SOAPException, XPathExpressionException, XMLSignatureException, InvalidAlgorithmParameterException, java.security.cert.CertificateException, NoSuchProviderException, KeyStoreException, IOException, UnrecoverableKeyException {
        Serializable payload = createRequest();

        SOAPMessage signedRequest = sign(
                marshall(
                        payload,
                        getMarshaller(payload.getClass())
                )
        );

        System.out.println("============ SIGNED SOAP MESSAGE ================");
        signedRequest.writeTo(System.out);
        System.out.println("\n=================================================");
    }

    private PrivateKey getPrivateKey() throws java.security.cert.CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(new FileInputStream("keystore.p12"), "123456".toCharArray());

        return (PrivateKey) ks.getKey(ks.aliases().nextElement(), "123456".toCharArray());
    }

    private X509Certificate getCertificate() throws CertificateException, KeyStoreException, NoSuchProviderException, java.security.cert.CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(new FileInputStream("keystore.p12"), "123456".toCharArray());

        return X509Certificate.getInstance(ks.getCertificate(ks.aliases().nextElement()).getEncoded());
    }
}