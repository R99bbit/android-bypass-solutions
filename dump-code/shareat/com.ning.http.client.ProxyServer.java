package com.ning.http.client;

import com.kakao.util.helper.CommonProtocol;
import com.ning.http.util.AsyncHttpProviderUtils;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ProxyServer {
    private String encoding;
    private final String host;
    private final List<String> nonProxyHosts;
    private String ntlmDomain;
    private final String password;
    private final int port;
    private final String principal;
    private final Protocol protocol;
    private final URI uri;

    public enum Protocol {
        HTTP("http"),
        HTTPS(CommonProtocol.URL_SCHEME),
        NTLM("NTLM"),
        KERBEROS("KERBEROS"),
        SPNEGO("SPNEGO");
        
        private final String protocol;

        private Protocol(String protocol2) {
            this.protocol = protocol2;
        }

        public String getProtocol() {
            return this.protocol;
        }

        public String toString() {
            return getProtocol();
        }
    }

    public ProxyServer(Protocol protocol2, String host2, int port2, String principal2, String password2) {
        this.nonProxyHosts = new ArrayList();
        this.encoding = "UTF-8";
        this.ntlmDomain = System.getProperty("http.auth.ntlm.domain", "");
        this.protocol = protocol2;
        this.host = host2;
        this.port = port2;
        this.principal = principal2;
        this.password = password2;
        this.uri = AsyncHttpProviderUtils.createUri(toString());
    }

    public ProxyServer(String host2, int port2, String principal2, String password2) {
        this(Protocol.HTTP, host2, port2, principal2, password2);
    }

    public ProxyServer(Protocol protocol2, String host2, int port2) {
        this(protocol2, host2, port2, null, null);
    }

    public ProxyServer(String host2, int port2) {
        this(Protocol.HTTP, host2, port2, null, null);
    }

    public Protocol getProtocol() {
        return this.protocol;
    }

    public String getProtocolAsString() {
        return this.protocol.toString();
    }

    public String getHost() {
        return this.host;
    }

    public int getPort() {
        return this.port;
    }

    public String getPrincipal() {
        return this.principal;
    }

    public String getPassword() {
        return this.password;
    }

    public URI getURI() {
        return this.uri;
    }

    public ProxyServer setEncoding(String encoding2) {
        this.encoding = encoding2;
        return this;
    }

    public String getEncoding() {
        return this.encoding;
    }

    public ProxyServer addNonProxyHost(String uri2) {
        this.nonProxyHosts.add(uri2);
        return this;
    }

    public ProxyServer removeNonProxyHost(String uri2) {
        this.nonProxyHosts.remove(uri2);
        return this;
    }

    public List<String> getNonProxyHosts() {
        return Collections.unmodifiableList(this.nonProxyHosts);
    }

    public ProxyServer setNtlmDomain(String ntlmDomain2) {
        this.ntlmDomain = ntlmDomain2;
        return this;
    }

    public String getNtlmDomain() {
        return this.ntlmDomain;
    }

    public String toString() {
        return this.protocol + "://" + this.host + ":" + this.port;
    }
}