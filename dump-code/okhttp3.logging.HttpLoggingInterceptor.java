package okhttp3.logging;

import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.util.concurrent.TimeUnit;
import okhttp3.Connection;
import okhttp3.Headers;
import okhttp3.Interceptor;
import okhttp3.Interceptor.Chain;
import okhttp3.MediaType;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.internal.http.HttpHeaders;
import okhttp3.internal.platform.Platform;
import okio.Buffer;
import okio.BufferedSource;

public final class HttpLoggingInterceptor implements Interceptor {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private volatile Level level;
    private final Logger logger;

    public enum Level {
        NONE,
        BASIC,
        HEADERS,
        BODY
    }

    public interface Logger {
        public static final Logger DEFAULT = new Logger() {
            public void log(String str) {
                Platform.get().log(4, str, null);
            }
        };

        void log(String str);
    }

    public HttpLoggingInterceptor() {
        this(Logger.DEFAULT);
    }

    public HttpLoggingInterceptor(Logger logger2) {
        this.level = Level.NONE;
        this.logger = logger2;
    }

    public HttpLoggingInterceptor setLevel(Level level2) {
        if (level2 != null) {
            this.level = level2;
            return this;
        }
        throw new NullPointerException("level == null. Use Level.NONE instead.");
    }

    public Level getLevel() {
        return this.level;
    }

    public Response intercept(Chain chain) throws IOException {
        boolean z;
        String str;
        String str2;
        boolean z2;
        Chain chain2 = chain;
        Level level2 = this.level;
        Request request = chain.request();
        if (level2 == Level.NONE) {
            return chain2.proceed(request);
        }
        boolean z3 = true;
        boolean z4 = level2 == Level.BODY;
        boolean z5 = z4 || level2 == Level.HEADERS;
        RequestBody body = request.body();
        if (body == null) {
            z3 = false;
        }
        Connection connection = chain.connection();
        Protocol protocol = connection != null ? connection.protocol() : Protocol.HTTP_1_1;
        StringBuilder sb = new StringBuilder();
        sb.append("--> ");
        sb.append(request.method());
        sb.append(' ');
        sb.append(request.url());
        sb.append(' ');
        sb.append(protocol);
        String sb2 = sb.toString();
        if (!z5 && z3) {
            StringBuilder sb3 = new StringBuilder();
            sb3.append(sb2);
            sb3.append(" (");
            sb3.append(body.contentLength());
            sb3.append("-byte body)");
            sb2 = sb3.toString();
        }
        this.logger.log(sb2);
        if (z5) {
            if (z3) {
                if (body.contentType() != null) {
                    Logger logger2 = this.logger;
                    StringBuilder sb4 = new StringBuilder();
                    sb4.append("Content-Type: ");
                    sb4.append(body.contentType());
                    logger2.log(sb4.toString());
                }
                if (body.contentLength() != -1) {
                    Logger logger3 = this.logger;
                    StringBuilder sb5 = new StringBuilder();
                    sb5.append("Content-Length: ");
                    sb5.append(body.contentLength());
                    logger3.log(sb5.toString());
                }
            }
            Headers headers = request.headers();
            int size = headers.size();
            int i = 0;
            while (i < size) {
                String name = headers.name(i);
                int i2 = size;
                if ("Content-Type".equalsIgnoreCase(name) || "Content-Length".equalsIgnoreCase(name)) {
                    z2 = z5;
                } else {
                    Logger logger4 = this.logger;
                    z2 = z5;
                    StringBuilder sb6 = new StringBuilder();
                    sb6.append(name);
                    sb6.append(": ");
                    sb6.append(headers.value(i));
                    logger4.log(sb6.toString());
                }
                i++;
                size = i2;
                z5 = z2;
            }
            z = z5;
            if (!z4 || !z3) {
                Logger logger5 = this.logger;
                StringBuilder sb7 = new StringBuilder();
                sb7.append("--> END ");
                sb7.append(request.method());
                logger5.log(sb7.toString());
            } else if (bodyEncoded(request.headers())) {
                Logger logger6 = this.logger;
                StringBuilder sb8 = new StringBuilder();
                sb8.append("--> END ");
                sb8.append(request.method());
                sb8.append(" (encoded body omitted)");
                logger6.log(sb8.toString());
            } else {
                Buffer buffer = new Buffer();
                body.writeTo(buffer);
                Charset charset = UTF8;
                MediaType contentType = body.contentType();
                if (contentType != null) {
                    charset = contentType.charset(UTF8);
                }
                this.logger.log("");
                if (isPlaintext(buffer)) {
                    this.logger.log(buffer.readString(charset));
                    Logger logger7 = this.logger;
                    StringBuilder sb9 = new StringBuilder();
                    sb9.append("--> END ");
                    sb9.append(request.method());
                    sb9.append(" (");
                    sb9.append(body.contentLength());
                    sb9.append("-byte body)");
                    logger7.log(sb9.toString());
                } else {
                    Logger logger8 = this.logger;
                    StringBuilder sb10 = new StringBuilder();
                    sb10.append("--> END ");
                    sb10.append(request.method());
                    sb10.append(" (binary ");
                    sb10.append(body.contentLength());
                    sb10.append("-byte body omitted)");
                    logger8.log(sb10.toString());
                }
            }
        } else {
            z = z5;
        }
        long nanoTime = System.nanoTime();
        try {
            Response proceed = chain2.proceed(request);
            long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - nanoTime);
            ResponseBody body2 = proceed.body();
            long contentLength = body2.contentLength();
            if (contentLength != -1) {
                StringBuilder sb11 = new StringBuilder();
                sb11.append(contentLength);
                sb11.append("-byte");
                str = sb11.toString();
            } else {
                str = "unknown-length";
            }
            Logger logger9 = this.logger;
            StringBuilder sb12 = new StringBuilder();
            r17 = "-byte body)";
            sb12.append("<-- ");
            sb12.append(proceed.code());
            sb12.append(' ');
            long j = contentLength;
            sb12.append(proceed.message());
            sb12.append(' ');
            sb12.append(proceed.request().url());
            sb12.append(" (");
            sb12.append(millis);
            sb12.append("ms");
            if (!z) {
                StringBuilder sb13 = new StringBuilder();
                sb13.append(", ");
                sb13.append(str);
                sb13.append(" body");
                str2 = sb13.toString();
            } else {
                str2 = "";
            }
            sb12.append(str2);
            sb12.append(')');
            logger9.log(sb12.toString());
            if (z) {
                Headers headers2 = proceed.headers();
                int size2 = headers2.size();
                for (int i3 = 0; i3 < size2; i3++) {
                    Logger logger10 = this.logger;
                    StringBuilder sb14 = new StringBuilder();
                    sb14.append(headers2.name(i3));
                    sb14.append(": ");
                    sb14.append(headers2.value(i3));
                    logger10.log(sb14.toString());
                }
                if (!z4 || !HttpHeaders.hasBody(proceed)) {
                    this.logger.log("<-- END HTTP");
                } else if (bodyEncoded(proceed.headers())) {
                    this.logger.log("<-- END HTTP (encoded body omitted)");
                } else {
                    BufferedSource source = body2.source();
                    source.request(Long.MAX_VALUE);
                    Buffer buffer2 = source.buffer();
                    Charset charset2 = UTF8;
                    MediaType contentType2 = body2.contentType();
                    if (contentType2 != null) {
                        try {
                            charset2 = contentType2.charset(UTF8);
                        } catch (UnsupportedCharsetException unused) {
                            this.logger.log("");
                            this.logger.log("Couldn't decode the response body; charset is likely malformed.");
                            this.logger.log("<-- END HTTP");
                            return proceed;
                        }
                    }
                    if (!isPlaintext(buffer2)) {
                        this.logger.log("");
                        Logger logger11 = this.logger;
                        StringBuilder sb15 = new StringBuilder();
                        sb15.append("<-- END HTTP (binary ");
                        sb15.append(buffer2.size());
                        sb15.append("-byte body omitted)");
                        logger11.log(sb15.toString());
                        return proceed;
                    }
                    if (j != 0) {
                        this.logger.log("");
                        this.logger.log(buffer2.clone().readString(charset2));
                    }
                    Logger logger12 = this.logger;
                    StringBuilder sb16 = new StringBuilder();
                    sb16.append("<-- END HTTP (");
                    sb16.append(buffer2.size());
                    r3 = "-byte body)";
                    sb16.append("-byte body)");
                    logger12.log(sb16.toString());
                }
            }
            return proceed;
        } catch (Exception e) {
            Exception exc = e;
            Logger logger13 = this.logger;
            StringBuilder sb17 = new StringBuilder();
            sb17.append("<-- HTTP FAILED: ");
            sb17.append(exc);
            logger13.log(sb17.toString());
            throw exc;
        }
    }

    static boolean isPlaintext(Buffer buffer) {
        try {
            Buffer buffer2 = new Buffer();
            buffer.copyTo(buffer2, 0, buffer.size() < 64 ? buffer.size() : 64);
            int i = 0;
            while (true) {
                if (i >= 16) {
                    break;
                } else if (buffer2.exhausted()) {
                    break;
                } else {
                    int readUtf8CodePoint = buffer2.readUtf8CodePoint();
                    if (Character.isISOControl(readUtf8CodePoint) && !Character.isWhitespace(readUtf8CodePoint)) {
                        return false;
                    }
                    i++;
                }
            }
            return true;
        } catch (EOFException unused) {
            return false;
        }
    }

    private boolean bodyEncoded(Headers headers) {
        String str = headers.get("Content-Encoding");
        return str != null && !str.equalsIgnoreCase("identity");
    }
}