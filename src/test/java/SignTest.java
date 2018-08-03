import util.KeyStorage;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import java.io.IOException;

public class SignTest {
    public static void main(String[] args){
        KeyStorage ks = new KeyStorage("PKCS12", "keystore.p12", "123456");
        SignImpl sign = new SignImpl(ks);


        String message = "Hello world";
        JAXBElement<? extends String> jaxbElement =
                new JAXBElement<String>(new QName("root-element"),
                        String.class, message);

        try {
            sign.sign(jaxbElement).writeTo(System.out);
        } catch (SOAPException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
