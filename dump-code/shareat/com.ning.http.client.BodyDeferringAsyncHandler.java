package com.ning.http.client;

import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.Response.ResponseBuilder;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

public class BodyDeferringAsyncHandler implements AsyncHandler<Response> {
    private final CountDownLatch headersArrived = new CountDownLatch(1);
    private final OutputStream output;
    private volatile Response response;
    private final ResponseBuilder responseBuilder = new ResponseBuilder();
    private boolean responseSet;
    private final Semaphore semaphore = new Semaphore(1);
    private volatile Throwable throwable;

    public static class BodyDeferringInputStream extends FilterInputStream {
        private final BodyDeferringAsyncHandler bdah;
        private final Future<Response> future;

        public BodyDeferringInputStream(Future<Response> future2, BodyDeferringAsyncHandler bdah2, InputStream in) {
            super(in);
            this.future = future2;
            this.bdah = bdah2;
        }

        public void close() throws IOException {
            super.close();
            try {
                getLastResponse();
            } catch (Exception e) {
                IOException ioe = new IOException(e.getMessage());
                ioe.initCause(e);
                throw ioe;
            }
        }

        public Response getAsapResponse() throws InterruptedException, IOException {
            return this.bdah.getResponse();
        }

        public Response getLastResponse() throws InterruptedException, ExecutionException {
            return this.future.get();
        }
    }

    public BodyDeferringAsyncHandler(OutputStream os) {
        this.output = os;
        this.responseSet = false;
    }

    public void onThrowable(Throwable t) {
        this.throwable = t;
        try {
            this.semaphore.acquire();
        } catch (InterruptedException e) {
        } finally {
            this.headersArrived.countDown();
            this.semaphore.release();
        }
        try {
            closeOut();
        } catch (IOException e2) {
        }
    }

    public STATE onStatusReceived(HttpResponseStatus responseStatus) throws Exception {
        this.responseBuilder.reset();
        this.responseBuilder.accumulate(responseStatus);
        return STATE.CONTINUE;
    }

    public STATE onHeadersReceived(HttpResponseHeaders headers) throws Exception {
        this.responseBuilder.accumulate(headers);
        return STATE.CONTINUE;
    }

    public STATE onBodyPartReceived(HttpResponseBodyPart bodyPart) throws Exception {
        if (!this.responseSet) {
            this.response = this.responseBuilder.build();
            this.responseSet = true;
            this.headersArrived.countDown();
        }
        bodyPart.writeTo(this.output);
        return STATE.CONTINUE;
    }

    /* access modifiers changed from: protected */
    public void closeOut() throws IOException {
        try {
            this.output.flush();
        } finally {
            this.output.close();
        }
    }

    public Response onCompleted() throws IOException {
        if (!this.responseSet) {
            this.response = this.responseBuilder.build();
            this.responseSet = true;
        }
        this.headersArrived.countDown();
        closeOut();
        try {
            this.semaphore.acquire();
            if (this.throwable == null) {
                return this.responseBuilder.build();
            }
            IOException ioe = new IOException(this.throwable.getMessage());
            ioe.initCause(this.throwable);
            throw ioe;
        } catch (InterruptedException e) {
            return null;
        } finally {
            this.semaphore.release();
        }
    }

    public Response getResponse() throws InterruptedException, IOException {
        this.headersArrived.await();
        try {
            this.semaphore.acquire();
            if (this.throwable == null) {
                return this.response;
            }
            IOException ioe = new IOException(this.throwable.getMessage());
            ioe.initCause(this.throwable);
            throw ioe;
        } finally {
            this.semaphore.release();
        }
    }
}