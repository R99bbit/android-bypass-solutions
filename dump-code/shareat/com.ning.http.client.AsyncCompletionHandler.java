package com.ning.http.client;

import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.Response.ResponseBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AsyncCompletionHandler<T> implements AsyncHandler<T>, ProgressAsyncHandler<T> {
    private final ResponseBuilder builder = new ResponseBuilder();
    private final Logger log = LoggerFactory.getLogger(AsyncCompletionHandlerBase.class);

    public abstract T onCompleted(Response response) throws Exception;

    public STATE onBodyPartReceived(HttpResponseBodyPart content) throws Exception {
        this.builder.accumulate(content);
        return STATE.CONTINUE;
    }

    public STATE onStatusReceived(HttpResponseStatus status) throws Exception {
        this.builder.reset();
        this.builder.accumulate(status);
        return STATE.CONTINUE;
    }

    public STATE onHeadersReceived(HttpResponseHeaders headers) throws Exception {
        this.builder.accumulate(headers);
        return STATE.CONTINUE;
    }

    public final T onCompleted() throws Exception {
        return onCompleted(this.builder.build());
    }

    public void onThrowable(Throwable t) {
        this.log.debug(t.getMessage(), t);
    }

    public STATE onHeaderWriteCompleted() {
        return STATE.CONTINUE;
    }

    public STATE onContentWriteCompleted() {
        return STATE.CONTINUE;
    }

    public STATE onContentWriteProgress(long amount, long current, long total) {
        return STATE.CONTINUE;
    }
}