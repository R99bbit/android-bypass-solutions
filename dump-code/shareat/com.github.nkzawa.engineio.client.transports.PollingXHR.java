package com.github.nkzawa.engineio.client.transports;

import com.github.nkzawa.emitter.Emitter;
import com.github.nkzawa.emitter.Emitter.Listener;
import com.github.nkzawa.engineio.client.Transport.Options;
import com.github.nkzawa.thread.EventThread;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

public class PollingXHR extends Polling {
    /* access modifiers changed from: private */
    public static final Logger logger = Logger.getLogger(PollingXHR.class.getName());
    private Request pollXhr;
    private Request sendXhr;

    public static class Request extends Emitter {
        public static final String EVENT_DATA = "data";
        public static final String EVENT_ERROR = "error";
        public static final String EVENT_REQUEST_HEADERS = "requestHeaders";
        public static final String EVENT_RESPONSE_HEADERS = "responseHeaders";
        public static final String EVENT_SUCCESS = "success";
        /* access modifiers changed from: private */
        public byte[] data;
        private HostnameVerifier hostnameVerifier;
        private String method;
        private SSLContext sslContext;
        private String uri;
        /* access modifiers changed from: private */
        public HttpURLConnection xhr;

        public static class Options {
            public byte[] data;
            public HostnameVerifier hostnameVerifier;
            public String method;
            public SSLContext sslContext;
            public String uri;
        }

        public Request(Options opts) {
            this.method = opts.method != null ? opts.method : HttpRequest.METHOD_GET;
            this.uri = opts.uri;
            this.data = opts.data;
            this.sslContext = opts.sslContext;
            this.hostnameVerifier = opts.hostnameVerifier;
        }

        public void create() {
            try {
                PollingXHR.logger.fine(String.format("xhr open %s: %s", new Object[]{this.method, this.uri}));
                this.xhr = (HttpURLConnection) new URL(this.uri).openConnection();
                this.xhr.setRequestMethod(this.method);
                this.xhr.setConnectTimeout(10000);
                if (this.xhr instanceof HttpsURLConnection) {
                    if (this.sslContext != null) {
                        ((HttpsURLConnection) this.xhr).setSSLSocketFactory(this.sslContext.getSocketFactory());
                    }
                    if (this.hostnameVerifier != null) {
                        ((HttpsURLConnection) this.xhr).setHostnameVerifier(this.hostnameVerifier);
                    }
                }
                Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                if (HttpRequest.METHOD_POST.equals(this.method)) {
                    this.xhr.setDoOutput(true);
                    headers.put("Content-type", new LinkedList(Arrays.asList(new String[]{"application/octet-stream"})));
                }
                onRequestHeaders(headers);
                for (Entry<String, List<String>> header : headers.entrySet()) {
                    for (String v : header.getValue()) {
                        this.xhr.addRequestProperty(header.getKey(), v);
                    }
                }
                PollingXHR.logger.fine(String.format("sending xhr with url %s | data %s", new Object[]{this.uri, this.data}));
                new Thread(new Runnable() {
                    /* JADX WARNING: Removed duplicated region for block: B:26:0x007d A[SYNTHETIC, Splitter:B:26:0x007d] */
                    public void run() {
                        OutputStream output = null;
                        try {
                            if (this.data != null) {
                                Request.this.xhr.setFixedLengthStreamingMode(this.data.length);
                                OutputStream output2 = new BufferedOutputStream(Request.this.xhr.getOutputStream());
                                try {
                                    output2.write(this.data);
                                    output2.flush();
                                    output = output2;
                                } catch (IOException e) {
                                    e = e;
                                    output = output2;
                                    try {
                                        this.onError(e);
                                        if (output != null) {
                                            try {
                                                output.close();
                                                return;
                                            } catch (IOException e2) {
                                                return;
                                            }
                                        } else {
                                            return;
                                        }
                                    } catch (Throwable th) {
                                        th = th;
                                        if (output != null) {
                                            try {
                                                output.close();
                                            } catch (IOException e3) {
                                            }
                                        }
                                        throw th;
                                    }
                                } catch (Throwable th2) {
                                    th = th2;
                                    output = output2;
                                    if (output != null) {
                                    }
                                    throw th;
                                }
                            }
                            this.onResponseHeaders(Request.this.xhr.getHeaderFields());
                            int statusCode = Request.this.xhr.getResponseCode();
                            if (200 == statusCode) {
                                this.onLoad();
                            } else {
                                this.onError(new IOException(Integer.toString(statusCode)));
                            }
                            if (output != null) {
                                try {
                                    output.close();
                                } catch (IOException e4) {
                                }
                            }
                        } catch (IOException e5) {
                            e = e5;
                        }
                    }
                }).start();
            } catch (IOException e) {
                onError(e);
            }
        }

        private void onSuccess() {
            emit("success", new Object[0]);
            cleanup();
        }

        private void onData(String data2) {
            emit("data", data2);
            onSuccess();
        }

        private void onData(byte[] data2) {
            emit("data", data2);
            onSuccess();
        }

        /* access modifiers changed from: private */
        public void onError(Exception err) {
            emit("error", err);
            cleanup();
        }

        private void onRequestHeaders(Map<String, List<String>> headers) {
            emit("requestHeaders", headers);
        }

        /* access modifiers changed from: private */
        public void onResponseHeaders(Map<String, List<String>> headers) {
            emit("responseHeaders", headers);
        }

        private void cleanup() {
            if (this.xhr != null) {
                this.xhr.disconnect();
                this.xhr = null;
            }
        }

        /* access modifiers changed from: private */
        /* JADX WARNING: Removed duplicated region for block: B:20:0x006e A[SYNTHETIC, Splitter:B:20:0x006e] */
        /* JADX WARNING: Removed duplicated region for block: B:23:0x0073 A[SYNTHETIC, Splitter:B:23:0x0073] */
        /* JADX WARNING: Removed duplicated region for block: B:47:0x00c8 A[SYNTHETIC, Splitter:B:47:0x00c8] */
        /* JADX WARNING: Removed duplicated region for block: B:50:0x00cd A[SYNTHETIC, Splitter:B:50:0x00cd] */
        /* JADX WARNING: Removed duplicated region for block: B:66:? A[RETURN, SYNTHETIC] */
        public void onLoad() {
            InputStream input = null;
            BufferedReader reader = null;
            try {
                if ("application/octet-stream".equalsIgnoreCase(this.xhr.getContentType())) {
                    InputStream input2 = new BufferedInputStream(this.xhr.getInputStream());
                    try {
                        List<byte[]> buffers = new ArrayList<>();
                        int capacity = 0;
                        byte[] buffer = new byte[1024];
                        while (true) {
                            int len = input2.read(buffer);
                            if (len <= 0) {
                                break;
                            }
                            byte[] _buffer = new byte[len];
                            System.arraycopy(buffer, 0, _buffer, 0, len);
                            buffers.add(_buffer);
                            capacity += len;
                        }
                        ByteBuffer data2 = ByteBuffer.allocate(capacity);
                        for (byte[] b : buffers) {
                            data2.put(b);
                        }
                        onData(data2.array());
                        input = input2;
                    } catch (IOException e) {
                        e = e;
                        input = input2;
                        try {
                            onError(e);
                            if (input != null) {
                                try {
                                    input.close();
                                } catch (IOException e2) {
                                }
                            }
                            if (reader != null) {
                                try {
                                    reader.close();
                                    return;
                                } catch (IOException e3) {
                                    return;
                                }
                            } else {
                                return;
                            }
                        } catch (Throwable th) {
                            th = th;
                            if (input != null) {
                            }
                            if (reader != null) {
                            }
                            throw th;
                        }
                    } catch (Throwable th2) {
                        th = th2;
                        input = input2;
                        if (input != null) {
                            try {
                                input.close();
                            } catch (IOException e4) {
                            }
                        }
                        if (reader != null) {
                            try {
                                reader.close();
                            } catch (IOException e5) {
                            }
                        }
                        throw th;
                    }
                } else {
                    StringBuilder data3 = new StringBuilder();
                    BufferedReader reader2 = new BufferedReader(new InputStreamReader(this.xhr.getInputStream()));
                    while (true) {
                        try {
                            String line = reader2.readLine();
                            if (line == null) {
                                break;
                            }
                            data3.append(line);
                        } catch (IOException e6) {
                            e = e6;
                            reader = reader2;
                            onError(e);
                            if (input != null) {
                            }
                            if (reader != null) {
                            }
                        } catch (Throwable th3) {
                            th = th3;
                            reader = reader2;
                            if (input != null) {
                            }
                            if (reader != null) {
                            }
                            throw th;
                        }
                    }
                    onData(data3.toString());
                    reader = reader2;
                }
                if (input != null) {
                    try {
                        input.close();
                    } catch (IOException e7) {
                    }
                }
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException e8) {
                    }
                }
            } catch (IOException e9) {
                e = e9;
                onError(e);
                if (input != null) {
                }
                if (reader != null) {
                }
            }
        }

        public void abort() {
            cleanup();
        }
    }

    public PollingXHR(Options opts) {
        super(opts);
    }

    /* access modifiers changed from: protected */
    public Request request() {
        return request(null);
    }

    /* access modifiers changed from: protected */
    public Request request(Options opts) {
        if (opts == null) {
            opts = new Options();
        }
        opts.uri = uri();
        opts.sslContext = this.sslContext;
        opts.hostnameVerifier = this.hostnameVerifier;
        Request req = new Request(opts);
        req.on("requestHeaders", new Listener() {
            public void call(Object... args) {
                this.emit("requestHeaders", args[0]);
            }
        }).on("responseHeaders", new Listener() {
            public void call(final Object... args) {
                EventThread.exec(new Runnable() {
                    public void run() {
                        this.emit("responseHeaders", args[0]);
                    }
                });
            }
        });
        return req;
    }

    /* access modifiers changed from: protected */
    public void doWrite(byte[] data, final Runnable fn) {
        Options opts = new Options();
        opts.method = HttpRequest.METHOD_POST;
        opts.data = data;
        Request req = request(opts);
        req.on("success", new Listener() {
            public void call(Object... args) {
                EventThread.exec(new Runnable() {
                    public void run() {
                        fn.run();
                    }
                });
            }
        });
        req.on("error", new Listener() {
            public void call(final Object... args) {
                EventThread.exec(new Runnable() {
                    public void run() {
                        this.onError("xhr post error", (args.length <= 0 || !(args[0] instanceof Exception)) ? null : (Exception) args[0]);
                    }
                });
            }
        });
        req.create();
        this.sendXhr = req;
    }

    /* access modifiers changed from: protected */
    public void doPoll() {
        logger.fine("xhr poll");
        Request req = request();
        req.on("data", new Listener() {
            public void call(final Object... args) {
                EventThread.exec(new Runnable() {
                    /* JADX WARNING: Multi-variable type inference failed */
                    public void run() {
                        Object arg = args.length > 0 ? args[0] : null;
                        if (arg instanceof String) {
                            this.onData((String) arg);
                        } else if (arg instanceof byte[]) {
                            this.onData((byte[]) (byte[]) arg);
                        }
                    }
                });
            }
        });
        req.on("error", new Listener() {
            public void call(final Object... args) {
                EventThread.exec(new Runnable() {
                    public void run() {
                        this.onError("xhr poll error", (args.length <= 0 || !(args[0] instanceof Exception)) ? null : (Exception) args[0]);
                    }
                });
            }
        });
        req.create();
        this.pollXhr = req;
    }
}