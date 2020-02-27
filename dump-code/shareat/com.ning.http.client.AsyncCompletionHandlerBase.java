package com.ning.http.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AsyncCompletionHandlerBase extends AsyncCompletionHandler<Response> {
    private final Logger log = LoggerFactory.getLogger(AsyncCompletionHandlerBase.class);

    public Response onCompleted(Response response) throws Exception {
        return response;
    }

    public void onThrowable(Throwable t) {
        this.log.debug(t.getMessage(), t);
    }
}