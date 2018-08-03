import org.w3c.dom.Document;
import util.SOAPBuilderConfig;

import javax.security.cert.X509Certificate;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.Serializable;
import java.security.PrivateKey;

public class SOAPBuilderFactory {
    public static SOAPBuilderImpl newInstance(final PrivateKey key, final String bodyId, final X509Certificate certificate, SOAPBuilderConfig config) throws JAXBException, ParserConfigurationException {
        SOAPBuilderImpl impl = new SOAPBuilderImpl() {
            @Override
            String getBodyId() {
                return bodyId;
            }

            @Override
            X509Certificate getCert() {
                return certificate;
            }

            @Override
            PrivateKey getPrivateKey() {
                return key;
            }
        };
        impl.setConfig(config);
        return  impl;
    }

}
