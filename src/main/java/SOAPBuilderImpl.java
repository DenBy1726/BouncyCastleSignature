import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import util.SOAPBuilderConfig;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
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
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Collections;

public abstract class SOAPBuilderImpl implements SOAPBuilder {

    private static final XPathFactory xPathFactory = XPathFactory.newInstance();
    private static final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    private static final XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");
    private static final KeyInfoFactory keyInfoFactory = XMLSignatureFactory.getInstance("DOM").getKeyInfoFactory();

    {
        documentBuilderFactory.setNamespaceAware(Boolean.TRUE);
    }

    private SOAPBuilderConfig config = new SOAPBuilderConfig();

    public SOAPBuilderConfig getConfig() {
        return config;
    }

    public void setConfig(SOAPBuilderConfig config) {
        this.config = config;
    }

    abstract String getBodyId();

    abstract X509Certificate getCert();

    abstract PrivateKey getPrivateKey();

    @Override
    public Element getBodyElementFrom(Node payload) throws XPathExpressionException {
        XPath xPath = xPathFactory.newXPath();

        return (Element) xPath.evaluate("//*[local-name()='Envelope']/*[local-name()='Body']", payload, XPathConstants.NODE);
    }

    @Override
    public Element getSecurityElementFrom(Node payload) throws XPathExpressionException {
        XPath xPath = xPathFactory.newXPath();

        return (Element) xPath.evaluate("/*[local-name()='Envelope']/*[local-name()='Header']/*[local-name()='Security']", payload, XPathConstants.NODE);
    }

    //entity to xml node
    protected static Node marshall(Serializable request) throws ParserConfigurationException, JAXBException {
        DOMResult domResult = new DOMResult();

        JAXBContext
                .newInstance(request.getClass())
                .createMarshaller()
                .marshal(request, domResult);

        return domResult.getNode().getFirstChild();
    }

    @Override
    public Document createDocument(Serializable value) throws JAXBException, ParserConfigurationException {
        Node request = marshall(value);
        //создание документа с объектом внутри
        Document document = documentBuilderFactory
                .newDocumentBuilder()
                .newDocument();
        document.appendChild(document.importNode(request, true));
        return document;
    }

    @Override
    public SOAPMessage createSoapMessage() throws SOAPException {
        return MessageFactory.newInstance().createMessage();
    }

    @Override
    public SOAPPart getSoapPart(SOAPMessage soapMessage) {
        return soapMessage.getSOAPPart();
    }

    @Override
    public SOAPBody getSoapBody(SOAPEnvelope soapEnvelope) throws SOAPException {
        SOAPBody soapBody = soapEnvelope.getBody();
        return soapBody;
    }

    public void addDocument(SOAPMessage message, Document document) throws SOAPException {
        getSoapBody(getSoapEnvelope(getSoapPart(message))).addDocument(document);
    }

    @Override
    public void tagSoapBody(SOAPBody soapBody, SOAPEnvelope soapEnvelope) throws SOAPException {
        soapBody.addAttribute(
                soapEnvelope.createName(
                        config.getSignatureId(),
                        config.getPrefixWSSecurity(),
                        config.getNsWSSecurity()
                ),
                getBodyId()
        );
    }

    @Override
    public SOAPEnvelope getSoapEnvelope(SOAPPart soapPart) throws SOAPException {
        return soapPart.getEnvelope();
    }

    @Override
    public void tagSoapEnvelope(SOAPEnvelope soapEnvelope) throws SOAPException {
        soapEnvelope.getHeader().addHeaderElement(
                soapEnvelope.createName(
                        config.getSecurity(),
                        config.getSecurityPrefix(),
                        config.getSecurityNamespaceUrl()
                )
        ).setMustUnderstand(Boolean.TRUE);
    }

    @Override
    public Node getRoot(SOAPPart soapPart) throws SOAPException {
        Source source = soapPart.getContent();
        return ((DOMSource) source).getNode();
    }

    @Override
    public Node getRoot(SOAPMessage soapMessage) throws SOAPException {
        return ((DOMSource) getSoapPart(soapMessage).getContent()).getNode();
    }


    @Override
    public SignedInfo getSignedInfo(Reference reference, CanonicalizationMethod canonicalizationMethod, SignatureMethod signatureMethod) {
        return xmlSignatureFactory.newSignedInfo(
                canonicalizationMethod,
                signatureMethod,
                Collections.singletonList(reference)
        );
    }

    @Override
    public KeyInfo getKeyInfo(KeyValue keyValue, X509IssuerSerial issuerSerial) {
        KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        return keyInfoFactory.newKeyInfo(Arrays.asList(keyValue, issuerSerial));
    }

    @Override
    public KeyValue getKeyValue() throws KeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, java.security.cert.CertificateException, IOException {
        return keyInfoFactory.newKeyValue(getCert().getPublicKey());
    }

    @Override
    public X509IssuerSerial getIssuerSerial() {
        return keyInfoFactory.newX509IssuerSerial(
                getCert().getIssuerDN().getName(),
                new BigInteger(config.getSerial()));
    }

    @Override
    public Reference getReference() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return xmlSignatureFactory.newReference("#" + getBodyId(),
                xmlSignatureFactory.newDigestMethod(DigestMethod.SHA1, null));
    }

    @Override
    public CanonicalizationMethod getCanonicalizationMethod() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return xmlSignatureFactory.newCanonicalizationMethod(
                CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                (C14NMethodParameterSpec) null);
    }

    @Override
    public SignatureMethod getSignatureMethod() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
    }

    @Override
    public SOAPMessage createSoapMessage(Document document) throws SOAPException {
        SOAPMessage soapMessage = createSoapMessage();
        SOAPPart soapPart = getSoapPart(soapMessage);
        SOAPEnvelope soapEnvelope = getSoapEnvelope(soapPart);
        SOAPBody soapBody = getSoapBody(soapEnvelope);
        addDocument(soapMessage,document);
        tagSoapEnvelope(soapEnvelope);
        tagSoapBody(soapBody,soapEnvelope);
        getRoot(soapPart);

        return soapMessage;
    }

    @Override
    public XMLSignature createSignature(SOAPMessage message) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyException, KeyStoreException, java.security.cert.CertificateException, NoSuchProviderException, CertificateException, IOException, SOAPException, XPathExpressionException {
        return xmlSignatureFactory.newXMLSignature(
                getSignedInfo(
                        getReference(),
                        getCanonicalizationMethod(),
                        getSignatureMethod()
                ),
                getKeyInfo(
                        getKeyValue(),
                        getIssuerSerial()
                ));
    }

    @Override
    public DOMSignContext createSignContext(SOAPMessage message) throws SOAPException, XPathExpressionException {
        DOMSignContext sigContext = new DOMSignContext(getPrivateKey(), getSecurityElementFrom(getRoot(message)));
        sigContext.putNamespacePrefix(XMLSignature.XMLNS, config.getPrefixWSSecurity());
        sigContext.setIdAttributeNS(getSoapBody(getSoapEnvelope(getSoapPart(message))), config.getNsWSSecurity(), config.getSignatureId());
        return sigContext;
    }


























}
