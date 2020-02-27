package com.ning.http.client.resumable;

import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilder;
import com.ning.http.client.Response.ResponseBuilder;
import com.ning.http.client.listener.TransferCompletionHandler;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResumableAsyncHandler<T> implements AsyncHandler<T> {
    private static final Logger logger = LoggerFactory.getLogger(TransferCompletionHandler.class);
    /* access modifiers changed from: private */
    public static Map<String, Long> resumableIndex;
    private static final ResumableIndexThread resumeIndexThread = new ResumableIndexThread();
    private final boolean accumulateBody;
    private final AtomicLong byteTransferred;
    private Integer contentLength;
    private final AsyncHandler<T> decoratedAsyncHandler;
    private ResponseBuilder responseBuilder;
    private ResumableListener resumableListener;
    private final ResumableProcessor resumableProcessor;
    private String url;

    private static class NULLResumableHandler implements ResumableProcessor {
        private NULLResumableHandler() {
        }

        public void put(String url, long transferredBytes) {
        }

        public void remove(String uri) {
        }

        public void save(Map<String, Long> map) {
        }

        public Map<String, Long> load() {
            return new HashMap();
        }
    }

    private static class NULLResumableListener implements ResumableListener {
        private long length;

        private NULLResumableListener() {
            this.length = 0;
        }

        public void onBytesReceived(ByteBuffer byteBuffer) throws IOException {
            this.length += (long) byteBuffer.remaining();
        }

        public void onAllBytesReceived() {
        }

        public long length() {
            return this.length;
        }
    }

    private static class ResumableIndexThread extends Thread {
        public final ConcurrentLinkedQueue<ResumableProcessor> resumableProcessors = new ConcurrentLinkedQueue<>();

        public ResumableIndexThread() {
            Runtime.getRuntime().addShutdownHook(this);
        }

        public void addResumableProcessor(ResumableProcessor p) {
            this.resumableProcessors.offer(p);
        }

        public void run() {
            Iterator i$ = this.resumableProcessors.iterator();
            while (i$.hasNext()) {
                i$.next().save(ResumableAsyncHandler.resumableIndex);
            }
        }
    }

    public interface ResumableProcessor {
        Map<String, Long> load();

        void put(String str, long j);

        void remove(String str);

        void save(Map<String, Long> map);
    }

    private ResumableAsyncHandler(long byteTransferred2, ResumableProcessor resumableProcessor2, AsyncHandler<T> decoratedAsyncHandler2, boolean accumulateBody2) {
        this.responseBuilder = new ResponseBuilder();
        this.resumableListener = new NULLResumableListener();
        this.byteTransferred = new AtomicLong(byteTransferred2);
        resumableProcessor2 = resumableProcessor2 == null ? new NULLResumableHandler() : resumableProcessor2;
        this.resumableProcessor = resumableProcessor2;
        resumableIndex = resumableProcessor2.load();
        resumeIndexThread.addResumableProcessor(resumableProcessor2);
        this.decoratedAsyncHandler = decoratedAsyncHandler2;
        this.accumulateBody = accumulateBody2;
    }

    public ResumableAsyncHandler(long byteTransferred2) {
        this(byteTransferred2, null, null, false);
    }

    public ResumableAsyncHandler(boolean accumulateBody2) {
        this(0, null, null, accumulateBody2);
    }

    public ResumableAsyncHandler() {
        this(0, null, null, false);
    }

    public ResumableAsyncHandler(AsyncHandler<T> decoratedAsyncHandler2) {
        this(0, new PropertiesBasedResumableProcessor(), decoratedAsyncHandler2, false);
    }

    public ResumableAsyncHandler(long byteTransferred2, AsyncHandler<T> decoratedAsyncHandler2) {
        this(byteTransferred2, new PropertiesBasedResumableProcessor(), decoratedAsyncHandler2, false);
    }

    public ResumableAsyncHandler(ResumableProcessor resumableProcessor2) {
        this(0, resumableProcessor2, null, false);
    }

    public ResumableAsyncHandler(ResumableProcessor resumableProcessor2, boolean accumulateBody2) {
        this(0, resumableProcessor2, null, accumulateBody2);
    }

    public STATE onStatusReceived(HttpResponseStatus status) throws Exception {
        this.responseBuilder.accumulate(status);
        if (status.getStatusCode() != 200 && status.getStatusCode() != 206) {
            return STATE.ABORT;
        }
        this.url = status.getUrl().toURL().toString();
        if (this.decoratedAsyncHandler != null) {
            return this.decoratedAsyncHandler.onStatusReceived(status);
        }
        return STATE.CONTINUE;
    }

    public void onThrowable(Throwable t) {
        if (this.decoratedAsyncHandler != null) {
            this.decoratedAsyncHandler.onThrowable(t);
        } else {
            logger.debug((String) "", t);
        }
    }

    public STATE onBodyPartReceived(HttpResponseBodyPart bodyPart) throws Exception {
        if (this.accumulateBody) {
            this.responseBuilder.accumulate(bodyPart);
        }
        STATE state = STATE.CONTINUE;
        try {
            this.resumableListener.onBytesReceived(bodyPart.getBodyByteBuffer());
            if (this.decoratedAsyncHandler != null) {
                state = this.decoratedAsyncHandler.onBodyPartReceived(bodyPart);
            }
            this.byteTransferred.addAndGet((long) bodyPart.getBodyPartBytes().length);
            this.resumableProcessor.put(this.url, this.byteTransferred.get());
            return state;
        } catch (IOException e) {
            return STATE.ABORT;
        }
    }

    public T onCompleted() throws Exception {
        this.resumableProcessor.remove(this.url);
        this.resumableListener.onAllBytesReceived();
        if (this.decoratedAsyncHandler != null) {
            this.decoratedAsyncHandler.onCompleted();
        }
        return this.responseBuilder.build();
    }

    public STATE onHeadersReceived(HttpResponseHeaders headers) throws Exception {
        this.responseBuilder.accumulate(headers);
        String contentLengthHeader = headers.getHeaders().getFirstValue("Content-Length");
        if (contentLengthHeader != null) {
            this.contentLength = Integer.valueOf(contentLengthHeader);
            if (this.contentLength == null || this.contentLength.intValue() == -1) {
                return STATE.ABORT;
            }
        }
        if (this.decoratedAsyncHandler != null) {
            return this.decoratedAsyncHandler.onHeadersReceived(headers);
        }
        return STATE.CONTINUE;
    }

    public Request adjustRequestRange(Request request) {
        if (resumableIndex.get(request.getUrl()) != null) {
            this.byteTransferred.set(resumableIndex.get(request.getUrl()).longValue());
        }
        if (!(this.resumableListener == null || this.resumableListener.length() <= 0 || this.byteTransferred.get() == this.resumableListener.length())) {
            this.byteTransferred.set(this.resumableListener.length());
        }
        RequestBuilder builder = new RequestBuilder(request);
        if (request.getHeaders().get((Object) "Range") == null && this.byteTransferred.get() != 0) {
            builder.setHeader((String) "Range", "bytes=" + this.byteTransferred.get() + "-");
        }
        return builder.build();
    }

    public ResumableAsyncHandler setResumableListener(ResumableListener resumableListener2) {
        this.resumableListener = resumableListener2;
        return this;
    }
}