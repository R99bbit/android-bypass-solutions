package com.ning.http.client.providers.grizzly;

import org.glassfish.grizzly.filterchain.FilterChainBuilder;
import org.glassfish.grizzly.nio.transport.TCPNIOTransport;

public interface TransportCustomizer {
    void customize(TCPNIOTransport tCPNIOTransport, FilterChainBuilder filterChainBuilder);
}