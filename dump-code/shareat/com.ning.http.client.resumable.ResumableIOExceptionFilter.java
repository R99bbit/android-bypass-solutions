package com.ning.http.client.resumable;

import com.ning.http.client.filter.FilterContext;
import com.ning.http.client.filter.FilterContext.FilterContextBuilder;
import com.ning.http.client.filter.FilterException;
import com.ning.http.client.filter.IOExceptionFilter;

public class ResumableIOExceptionFilter implements IOExceptionFilter {
    public FilterContext filter(FilterContext ctx) throws FilterException {
        if (ctx.getIOException() == null || !(ctx.getAsyncHandler() instanceof ResumableAsyncHandler)) {
            return ctx;
        }
        return new FilterContextBuilder(ctx).request(ResumableAsyncHandler.class.cast(ctx.getAsyncHandler()).adjustRequestRange(ctx.getRequest())).replayRequest(true).build();
    }
}