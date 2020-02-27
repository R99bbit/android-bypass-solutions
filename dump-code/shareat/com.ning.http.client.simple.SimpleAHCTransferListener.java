package com.ning.http.client.simple;

public interface SimpleAHCTransferListener {
    void onBytesReceived(String str, long j, long j2, long j3);

    void onBytesSent(String str, long j, long j2, long j3);

    void onCompleted(String str, int i, String str2);

    void onHeaders(String str, HeaderMap headerMap);

    void onStatus(String str, int i, String str2);
}