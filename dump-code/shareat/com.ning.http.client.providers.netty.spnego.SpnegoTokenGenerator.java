package com.ning.http.client.providers.netty.spnego;

import java.io.IOException;

public interface SpnegoTokenGenerator {
    byte[] generateSpnegoDERObject(byte[] bArr) throws IOException;
}