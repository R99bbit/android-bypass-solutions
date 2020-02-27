package com.squareup.okhttp.internal.http;

import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.Response.Builder;
import com.squareup.okhttp.ResponseBody;
import java.io.IOException;
import okio.Okio;
import okio.Sink;
import okio.Source;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;

public final class HttpTransport implements Transport {
    private final HttpConnection httpConnection;
    private final HttpEngine httpEngine;

    public HttpTransport(HttpEngine httpEngine2, HttpConnection httpConnection2) {
        this.httpEngine = httpEngine2;
        this.httpConnection = httpConnection2;
    }

    public Sink createRequestBody(Request request, long contentLength) throws IOException {
        if (Values.CHUNKED.equalsIgnoreCase(request.header(Names.TRANSFER_ENCODING))) {
            return this.httpConnection.newChunkedSink();
        }
        if (contentLength != -1) {
            return this.httpConnection.newFixedLengthSink(contentLength);
        }
        throw new IllegalStateException("Cannot stream a request body without chunked encoding or a known content length!");
    }

    public void finishRequest() throws IOException {
        this.httpConnection.flush();
    }

    public void writeRequestBody(RetryableSink requestBody) throws IOException {
        this.httpConnection.writeRequestBody(requestBody);
    }

    public void writeRequestHeaders(Request request) throws IOException {
        this.httpEngine.writingRequestHeaders();
        this.httpConnection.writeRequest(request.headers(), RequestLine.get(request, this.httpEngine.getConnection().getRoute().getProxy().type(), this.httpEngine.getConnection().getProtocol()));
    }

    public Builder readResponseHeaders() throws IOException {
        return this.httpConnection.readResponse();
    }

    public void releaseConnectionOnIdle() throws IOException {
        if (canReuseConnection()) {
            this.httpConnection.poolOnIdle();
        } else {
            this.httpConnection.closeOnIdle();
        }
    }

    public boolean canReuseConnection() {
        if (!"close".equalsIgnoreCase(this.httpEngine.getRequest().header("Connection")) && !"close".equalsIgnoreCase(this.httpEngine.getResponse().header("Connection")) && !this.httpConnection.isClosed()) {
            return true;
        }
        return false;
    }

    public ResponseBody openResponseBody(Response response) throws IOException {
        return new RealResponseBody(response.headers(), Okio.buffer(getTransferStream(response)));
    }

    private Source getTransferStream(Response response) throws IOException {
        if (!HttpEngine.hasBody(response)) {
            return this.httpConnection.newFixedLengthSource(0);
        }
        if (Values.CHUNKED.equalsIgnoreCase(response.header(Names.TRANSFER_ENCODING))) {
            return this.httpConnection.newChunkedSource(this.httpEngine);
        }
        long contentLength = OkHeaders.contentLength(response);
        if (contentLength != -1) {
            return this.httpConnection.newFixedLengthSource(contentLength);
        }
        return this.httpConnection.newUnknownLengthSource();
    }

    public void disconnect(HttpEngine engine) throws IOException {
        this.httpConnection.closeIfOwnedBy(engine);
    }
}