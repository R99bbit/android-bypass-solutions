package com.squareup.okhttp.internal.http;

import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.Response.Builder;
import com.squareup.okhttp.ResponseBody;
import java.io.IOException;
import okio.Sink;

public interface Transport {
    public static final int DISCARD_STREAM_TIMEOUT_MILLIS = 100;

    boolean canReuseConnection();

    Sink createRequestBody(Request request, long j) throws IOException;

    void disconnect(HttpEngine httpEngine) throws IOException;

    void finishRequest() throws IOException;

    ResponseBody openResponseBody(Response response) throws IOException;

    Builder readResponseHeaders() throws IOException;

    void releaseConnectionOnIdle() throws IOException;

    void writeRequestBody(RetryableSink retryableSink) throws IOException;

    void writeRequestHeaders(Request request) throws IOException;
}