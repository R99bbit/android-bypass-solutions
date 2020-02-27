package com.ning.http.client;

import java.io.IOException;
import java.util.List;

public interface AsyncHttpProvider {
    void close();

    <T> ListenableFuture<T> execute(Request request, AsyncHandler<T> asyncHandler) throws IOException;

    Response prepareResponse(HttpResponseStatus httpResponseStatus, HttpResponseHeaders httpResponseHeaders, List<HttpResponseBodyPart> list);
}