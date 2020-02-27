package com.ning.http.client.listener;

import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import java.io.IOException;
import java.nio.ByteBuffer;

public interface TransferListener {
    void onBytesReceived(ByteBuffer byteBuffer) throws IOException;

    void onBytesSent(ByteBuffer byteBuffer);

    void onRequestHeadersSent(FluentCaseInsensitiveStringsMap fluentCaseInsensitiveStringsMap);

    void onRequestResponseCompleted();

    void onResponseHeadersReceived(FluentCaseInsensitiveStringsMap fluentCaseInsensitiveStringsMap);

    void onThrowable(Throwable th);
}