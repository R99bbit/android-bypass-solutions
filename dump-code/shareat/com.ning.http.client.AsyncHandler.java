package com.ning.http.client;

public interface AsyncHandler<T> {

    public enum STATE {
        ABORT,
        CONTINUE,
        UPGRADE
    }

    STATE onBodyPartReceived(HttpResponseBodyPart httpResponseBodyPart) throws Exception;

    T onCompleted() throws Exception;

    STATE onHeadersReceived(HttpResponseHeaders httpResponseHeaders) throws Exception;

    STATE onStatusReceived(HttpResponseStatus httpResponseStatus) throws Exception;

    void onThrowable(Throwable th);
}