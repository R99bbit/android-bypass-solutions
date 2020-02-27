package com.ning.http.client.filter;

import com.ning.http.client.AsyncHandler;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.Request;
import java.io.IOException;

public class FilterContext<T> {
    private final FilterContextBuilder b;

    public static class FilterContextBuilder<T> {
        /* access modifiers changed from: private */
        public AsyncHandler<T> asyncHandler = null;
        /* access modifiers changed from: private */
        public HttpResponseHeaders headers;
        /* access modifiers changed from: private */
        public IOException ioException = null;
        /* access modifiers changed from: private */
        public boolean replayRequest = false;
        /* access modifiers changed from: private */
        public Request request = null;
        /* access modifiers changed from: private */
        public HttpResponseStatus responseStatus = null;

        public FilterContextBuilder() {
        }

        public FilterContextBuilder(FilterContext clone) {
            this.asyncHandler = clone.getAsyncHandler();
            this.request = clone.getRequest();
            this.responseStatus = clone.getResponseStatus();
            this.replayRequest = clone.replayRequest();
            this.ioException = clone.getIOException();
        }

        public AsyncHandler<T> getAsyncHandler() {
            return this.asyncHandler;
        }

        public FilterContextBuilder asyncHandler(AsyncHandler<T> asyncHandler2) {
            this.asyncHandler = asyncHandler2;
            return this;
        }

        public Request getRequest() {
            return this.request;
        }

        public FilterContextBuilder request(Request request2) {
            this.request = request2;
            return this;
        }

        public FilterContextBuilder responseStatus(HttpResponseStatus responseStatus2) {
            this.responseStatus = responseStatus2;
            return this;
        }

        public FilterContextBuilder responseHeaders(HttpResponseHeaders headers2) {
            this.headers = headers2;
            return this;
        }

        public FilterContextBuilder replayRequest(boolean replayRequest2) {
            this.replayRequest = replayRequest2;
            return this;
        }

        public FilterContextBuilder ioException(IOException ioException2) {
            this.ioException = ioException2;
            return this;
        }

        public FilterContext build() {
            return new FilterContext(this);
        }
    }

    private FilterContext(FilterContextBuilder b2) {
        this.b = b2;
    }

    public AsyncHandler<T> getAsyncHandler() {
        return this.b.asyncHandler;
    }

    public Request getRequest() {
        return this.b.request;
    }

    public HttpResponseStatus getResponseStatus() {
        return this.b.responseStatus;
    }

    public HttpResponseHeaders getResponseHeaders() {
        return this.b.headers;
    }

    public boolean replayRequest() {
        return this.b.replayRequest;
    }

    public IOException getIOException() {
        return this.b.ioException;
    }
}