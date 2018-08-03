import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.security.cert.CertificateException;
import javax.xml.bind.JAXBException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.*;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.io.Serializable;
import java.security.*;

public interface SOAPBuilder {

    Element getBodyElementFrom(Node payload) throws XPathExpressionException;

    Element getSecurityElementFrom(Node payload) throws XPathExpressionException;

    Document createDocument(Serializable value) throws JAXBException, ParserConfigurationException;

    SOAPMessage createSoapMessage() throws SOAPException;

    SOAPPart getSoapPart(SOAPMessage soapMessage);

    SOAPBody getSoapBody(SOAPEnvelope soapEnvelope) throws SOAPException;

    void tagSoapBody(SOAPBody soapBody, SOAPEnvelope soapEnvelope) throws SOAPException;

    SOAPEnvelope getSoapEnvelope(SOAPPart soapPart) throws SOAPException;

    void tagSoapEnvelope(SOAPEnvelope soapEnvelope) throws SOAPException;

    Node getRoot(SOAPPart soapPart) throws SOAPException;

    Node getRoot(SOAPMessage soapMessage) throws SOAPException;

    SignedInfo getSignedInfo(Reference reference, CanonicalizationMethod canonicalizationMethod, SignatureMethod signatureMethod);

    KeyInfo getKeyInfo(KeyValue keyValue, X509IssuerSerial issuerSerial);

    KeyValue getKeyValue() throws KeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, java.security.cert.CertificateException, IOException;

    X509IssuerSerial getIssuerSerial();

    Reference getReference() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException;

    CanonicalizationMethod getCanonicalizationMethod() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException;

    SignatureMethod getSignatureMethod() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException;

    SOAPMessage createSoapMessage(Document document) throws SOAPException;

    XMLSignature createSignature(SOAPMessage message) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyException, KeyStoreException, java.security.cert.CertificateException, NoSuchProviderException, CertificateException, IOException, SOAPException, XPathExpressionException;

    DOMSignContext createSignContext(SOAPMessage message) throws SOAPException, XPathExpressionException;
}
