package a.b.a.b;

import java.io.IOException;
import okhttp3.MediaType;
import okhttp3.RequestBody;
import okio.BufferedSink;
import okio.GzipSink;
import okio.Okio;
import okio.Sink;

/* compiled from: CloudManager */
public class k extends RequestBody {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ RequestBody f14a;

    public k(a aVar, RequestBody requestBody) {
        this.f14a = requestBody;
    }

    public long contentLength() {
        return -1;
    }

    public MediaType contentType() {
        return this.f14a.contentType();
    }

    public void writeTo(BufferedSink bufferedSink) throws IOException {
        BufferedSink buffer = Okio.buffer((Sink) new GzipSink(bufferedSink));
        this.f14a.writeTo(buffer);
        buffer.close();
    }
}