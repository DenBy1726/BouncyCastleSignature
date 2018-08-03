package util;

public class SOAPBuilderConfig {
    private String nsWSSecurity = "http://schemas.xmlsoap.org/soap/security/2000-12";
    private String prefixWSSecurity = "ds";
    private String signatureId = "id";
    private String security = "Security";
    private String securityPrefix = "wsse";
    private String securityNamespaceUrl = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private String serial = "1234";

    public String getNsWSSecurity() {
        return nsWSSecurity;
    }

    public void setNsWSSecurity(String nsWSSecurity) {
        this.nsWSSecurity = nsWSSecurity;
    }

    public String getPrefixWSSecurity() {
        return prefixWSSecurity;
    }

    public void setPrefixWSSecurity(String prefixWSSecurity) {
        this.prefixWSSecurity = prefixWSSecurity;
    }

    public String getSignatureId() {
        return signatureId;
    }

    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }

    public String getSecurity() {
        return security;
    }

    public void setSecurity(String security) {
        this.security = security;
    }

    public String getSecurityPrefix() {
        return securityPrefix;
    }

    public void setSecurityPrefix(String securityPrefix) {
        this.securityPrefix = securityPrefix;
    }

    public String getSecurityNamespaceUrl() {
        return securityNamespaceUrl;
    }

    public void setSecurityNamespaceUrl(String securityNamespaceUrl) {
        this.securityNamespaceUrl = securityNamespaceUrl;
    }

    public String getSerial() {
        return serial;
    }

    public void setSerial(String serial) {
        this.serial = serial;
    }
}
