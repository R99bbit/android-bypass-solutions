package com.github.nkzawa.socketio.client;

import com.github.nkzawa.backo.Backoff;
import com.github.nkzawa.emitter.Emitter;
import com.github.nkzawa.emitter.Emitter.Listener;
import com.github.nkzawa.engineio.client.Socket;
import com.github.nkzawa.socketio.client.On.Handle;
import com.github.nkzawa.socketio.parser.Packet;
import com.github.nkzawa.socketio.parser.Parser.Decoder;
import com.github.nkzawa.socketio.parser.Parser.Encoder;
import com.github.nkzawa.socketio.parser.Parser.Encoder.Callback;
import com.github.nkzawa.thread.EventThread;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import org.jboss.netty.handler.codec.rtsp.RtspHeaders.Values;

public class Manager extends Emitter {
    public static final String EVENT_CLOSE = "close";
    public static final String EVENT_CONNECT_ERROR = "connect_error";
    public static final String EVENT_CONNECT_TIMEOUT = "connect_timeout";
    public static final String EVENT_ERROR = "error";
    public static final String EVENT_OPEN = "open";
    public static final String EVENT_PACKET = "packet";
    public static final String EVENT_RECONNECT = "reconnect";
    public static final String EVENT_RECONNECTING = "reconnecting";
    public static final String EVENT_RECONNECT_ATTEMPT = "reconnect_attempt";
    public static final String EVENT_RECONNECT_ERROR = "reconnect_error";
    public static final String EVENT_RECONNECT_FAILED = "reconnect_failed";
    public static final String EVENT_TRANSPORT = "transport";
    static HostnameVerifier defaultHostnameVerifier;
    static SSLContext defaultSSLContext;
    /* access modifiers changed from: private */
    public static final Logger logger = Logger.getLogger(Manager.class.getName());
    private double _randomizationFactor;
    private boolean _reconnection;
    private int _reconnectionAttempts;
    private long _reconnectionDelay;
    private long _reconnectionDelayMax;
    /* access modifiers changed from: private */
    public long _timeout;
    /* access modifiers changed from: private */
    public Backoff backoff;
    /* access modifiers changed from: private */
    public Set<Socket> connected;
    private Decoder decoder;
    private Encoder encoder;
    /* access modifiers changed from: private */
    public boolean encoding;
    Socket engine;
    private ConcurrentHashMap<String, Socket> nsps;
    /* access modifiers changed from: private */
    public Options opts;
    private List<Packet> packetBuffer;
    ReadyState readyState;
    /* access modifiers changed from: private */
    public boolean reconnecting;
    /* access modifiers changed from: private */
    public boolean skipReconnect;
    /* access modifiers changed from: private */
    public Queue<Handle> subs;
    /* access modifiers changed from: private */
    public URI uri;

    private static class Engine extends Socket {
        Engine(URI uri, com.github.nkzawa.engineio.client.Socket.Options opts) {
            super(uri, opts);
        }
    }

    public interface OpenCallback {
        void call(Exception exc);
    }

    public static class Options extends com.github.nkzawa.engineio.client.Socket.Options {
        public double randomizationFactor;
        public boolean reconnection = true;
        public int reconnectionAttempts;
        public long reconnectionDelay;
        public long reconnectionDelayMax;
        public long timeout = 20000;
    }

    enum ReadyState {
        CLOSED,
        OPENING,
        OPEN
    }

    public Manager() {
        this(null, null);
    }

    public Manager(URI uri2) {
        this(uri2, null);
    }

    public Manager(Options opts2) {
        this(null, opts2);
    }

    public Manager(URI uri2, Options opts2) {
        this.readyState = null;
        opts2 = opts2 == null ? new Options() : opts2;
        if (opts2.path == null) {
            opts2.path = "/socket.io";
        }
        if (opts2.sslContext == null) {
            opts2.sslContext = defaultSSLContext;
        }
        if (opts2.hostnameVerifier == null) {
            opts2.hostnameVerifier = defaultHostnameVerifier;
        }
        this.opts = opts2;
        this.nsps = new ConcurrentHashMap<>();
        this.subs = new LinkedList();
        reconnection(opts2.reconnection);
        reconnectionAttempts(opts2.reconnectionAttempts != 0 ? opts2.reconnectionAttempts : ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED);
        reconnectionDelay(opts2.reconnectionDelay != 0 ? opts2.reconnectionDelay : 1000);
        reconnectionDelayMax(opts2.reconnectionDelayMax != 0 ? opts2.reconnectionDelayMax : 5000);
        randomizationFactor(opts2.randomizationFactor != 0.0d ? opts2.randomizationFactor : 0.5d);
        this.backoff = new Backoff().setMin(reconnectionDelay()).setMax(reconnectionDelayMax()).setJitter(randomizationFactor());
        timeout(opts2.timeout);
        this.readyState = ReadyState.CLOSED;
        this.uri = uri2;
        this.connected = new HashSet();
        this.encoding = false;
        this.packetBuffer = new ArrayList();
        this.encoder = new Encoder();
        this.decoder = new Decoder();
    }

    /* access modifiers changed from: private */
    public void emitAll(String event, Object... args) {
        emit(event, args);
        for (Socket socket : this.nsps.values()) {
            socket.emit(event, args);
        }
    }

    private void updateSocketIds() {
        for (Socket socket : this.nsps.values()) {
            socket.id = this.engine.id();
        }
    }

    public boolean reconnection() {
        return this._reconnection;
    }

    public Manager reconnection(boolean v) {
        this._reconnection = v;
        return this;
    }

    public int reconnectionAttempts() {
        return this._reconnectionAttempts;
    }

    public Manager reconnectionAttempts(int v) {
        this._reconnectionAttempts = v;
        return this;
    }

    public long reconnectionDelay() {
        return this._reconnectionDelay;
    }

    public Manager reconnectionDelay(long v) {
        this._reconnectionDelay = v;
        if (this.backoff != null) {
            this.backoff.setMin(v);
        }
        return this;
    }

    public double randomizationFactor() {
        return this._randomizationFactor;
    }

    public Manager randomizationFactor(double v) {
        this._randomizationFactor = v;
        if (this.backoff != null) {
            this.backoff.setJitter(v);
        }
        return this;
    }

    public long reconnectionDelayMax() {
        return this._reconnectionDelayMax;
    }

    public Manager reconnectionDelayMax(long v) {
        this._reconnectionDelayMax = v;
        if (this.backoff != null) {
            this.backoff.setMax(v);
        }
        return this;
    }

    public long timeout() {
        return this._timeout;
    }

    public Manager timeout(long v) {
        this._timeout = v;
        return this;
    }

    /* access modifiers changed from: private */
    public void maybeReconnectOnOpen() {
        if (!this.reconnecting && this._reconnection && this.backoff.getAttempts() == 0) {
            reconnect();
        }
    }

    public Manager open() {
        return open(null);
    }

    public Manager open(final OpenCallback fn) {
        EventThread.exec(new Runnable() {
            public void run() {
                Manager.logger.fine(String.format("readyState %s", new Object[]{Manager.this.readyState}));
                if (Manager.this.readyState != ReadyState.OPEN && Manager.this.readyState != ReadyState.OPENING) {
                    Manager.logger.fine(String.format("opening %s", new Object[]{Manager.this.uri}));
                    Manager.this.engine = new Engine(Manager.this.uri, Manager.this.opts);
                    final Socket socket = Manager.this.engine;
                    final Manager self = Manager.this;
                    Manager.this.readyState = ReadyState.OPENING;
                    Manager.this.skipReconnect = false;
                    socket.on("transport", new Listener() {
                        public void call(Object... args) {
                            self.emit("transport", args);
                        }
                    });
                    final Handle openSub = On.on(socket, "open", new Listener() {
                        public void call(Object... objects) {
                            self.onopen();
                            if (fn != null) {
                                fn.call(null);
                            }
                        }
                    });
                    Handle errorSub = On.on(socket, "error", new Listener() {
                        public void call(Object... objects) {
                            Exception exc;
                            Object data = objects.length > 0 ? objects[0] : null;
                            Manager.logger.fine("connect_error");
                            self.cleanup();
                            self.readyState = ReadyState.CLOSED;
                            self.emitAll("connect_error", data);
                            if (fn != null) {
                                if (data instanceof Exception) {
                                    exc = (Exception) data;
                                } else {
                                    exc = null;
                                }
                                fn.call(new SocketIOException("Connection error", exc));
                                return;
                            }
                            self.maybeReconnectOnOpen();
                        }
                    });
                    if (Manager.this._timeout >= 0) {
                        final long timeout = Manager.this._timeout;
                        Manager.logger.fine(String.format("connection attempt will timeout after %d", new Object[]{Long.valueOf(timeout)}));
                        final Timer timer = new Timer();
                        timer.schedule(new TimerTask() {
                            public void run() {
                                EventThread.exec(new Runnable() {
                                    public void run() {
                                        Manager.logger.fine(String.format("connect attempt timed out after %d", new Object[]{Long.valueOf(timeout)}));
                                        openSub.destroy();
                                        socket.close();
                                        socket.emit("error", new SocketIOException((String) Values.TIMEOUT));
                                        self.emitAll("connect_timeout", Long.valueOf(timeout));
                                    }
                                });
                            }
                        }, timeout);
                        Manager.this.subs.add(new Handle() {
                            public void destroy() {
                                timer.cancel();
                            }
                        });
                    }
                    Manager.this.subs.add(openSub);
                    Manager.this.subs.add(errorSub);
                    Manager.this.engine.open();
                }
            }
        });
        return this;
    }

    /* access modifiers changed from: private */
    public void onopen() {
        logger.fine("open");
        cleanup();
        this.readyState = ReadyState.OPEN;
        emit("open", new Object[0]);
        Socket socket = this.engine;
        this.subs.add(On.on(socket, "data", new Listener() {
            public void call(Object... objects) {
                Object data = objects[0];
                if (data instanceof String) {
                    Manager.this.ondata((String) data);
                } else if (data instanceof byte[]) {
                    Manager.this.ondata((byte[]) (byte[]) data);
                }
            }
        }));
        this.subs.add(On.on(this.decoder, Decoder.EVENT_DECODED, new Listener() {
            public void call(Object... objects) {
                Manager.this.ondecoded(objects[0]);
            }
        }));
        this.subs.add(On.on(socket, "error", new Listener() {
            public void call(Object... objects) {
                Manager.this.onerror(objects[0]);
            }
        }));
        this.subs.add(On.on(socket, "close", new Listener() {
            public void call(Object... objects) {
                Manager.this.onclose(objects[0]);
            }
        }));
    }

    /* access modifiers changed from: private */
    public void ondata(String data) {
        this.decoder.add(data);
    }

    /* access modifiers changed from: private */
    public void ondata(byte[] data) {
        this.decoder.add(data);
    }

    /* access modifiers changed from: private */
    public void ondecoded(Packet packet) {
        emit("packet", packet);
    }

    /* access modifiers changed from: private */
    public void onerror(Exception err) {
        logger.log(Level.FINE, "error", err);
        emitAll("error", err);
    }

    public Socket socket(String nsp) {
        Socket socket = this.nsps.get(nsp);
        if (socket != null) {
            return socket;
        }
        Socket socket2 = new Socket(this, nsp);
        Socket _socket = this.nsps.putIfAbsent(nsp, socket2);
        if (_socket != null) {
            return _socket;
        }
        final Socket s = socket2;
        socket2.on(Socket.EVENT_CONNECT, new Listener() {
            public void call(Object... objects) {
                s.id = this.engine.id();
                this.connected.add(s);
            }
        });
        return socket2;
    }

    /* access modifiers changed from: 0000 */
    public void destroy(Socket socket) {
        this.connected.remove(socket);
        if (this.connected.size() <= 0) {
            close();
        }
    }

    /* access modifiers changed from: 0000 */
    public void packet(Packet packet) {
        logger.fine(String.format("writing packet %s", new Object[]{packet}));
        if (!this.encoding) {
            this.encoding = true;
            this.encoder.encode(packet, new Callback() {
                public void call(Object[] encodedPackets) {
                    Object[] arr$;
                    for (Object packet : encodedPackets) {
                        if (packet instanceof String) {
                            this.engine.write((String) packet);
                        } else if (packet instanceof byte[]) {
                            this.engine.write((byte[]) (byte[]) packet);
                        }
                    }
                    this.encoding = false;
                    this.processPacketQueue();
                }
            });
            return;
        }
        this.packetBuffer.add(packet);
    }

    /* access modifiers changed from: private */
    public void processPacketQueue() {
        if (this.packetBuffer.size() > 0 && !this.encoding) {
            packet(this.packetBuffer.remove(0));
        }
    }

    /* access modifiers changed from: private */
    public void cleanup() {
        while (true) {
            Handle sub = this.subs.poll();
            if (sub != null) {
                sub.destroy();
            } else {
                return;
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void close() {
        if (this.readyState != ReadyState.OPEN) {
            cleanup();
        }
        this.skipReconnect = true;
        this.backoff.reset();
        this.readyState = ReadyState.CLOSED;
        if (this.engine != null) {
            this.engine.close();
        }
    }

    /* access modifiers changed from: private */
    public void onclose(String reason) {
        logger.fine("close");
        cleanup();
        this.backoff.reset();
        this.readyState = ReadyState.CLOSED;
        emit("close", reason);
        if (this._reconnection && !this.skipReconnect) {
            reconnect();
        }
    }

    /* access modifiers changed from: private */
    public void reconnect() {
        if (!this.reconnecting && !this.skipReconnect) {
            if (this.backoff.getAttempts() >= this._reconnectionAttempts) {
                logger.fine("reconnect failed");
                this.backoff.reset();
                emitAll("reconnect_failed", new Object[0]);
                this.reconnecting = false;
                return;
            }
            long delay = this.backoff.duration();
            logger.fine(String.format("will wait %dms before reconnect attempt", new Object[]{Long.valueOf(delay)}));
            this.reconnecting = true;
            final Timer timer = new Timer();
            timer.schedule(new TimerTask() {
                public void run() {
                    EventThread.exec(new Runnable() {
                        public void run() {
                            if (!this.skipReconnect) {
                                Manager.logger.fine("attempting reconnect");
                                int attempts = this.backoff.getAttempts();
                                this.emitAll("reconnect_attempt", Integer.valueOf(attempts));
                                this.emitAll("reconnecting", Integer.valueOf(attempts));
                                if (!this.skipReconnect) {
                                    this.open(new OpenCallback() {
                                        public void call(Exception err) {
                                            if (err != null) {
                                                Manager.logger.fine("reconnect attempt error");
                                                this.reconnecting = false;
                                                this.reconnect();
                                                this.emitAll("reconnect_error", err);
                                                return;
                                            }
                                            Manager.logger.fine("reconnect success");
                                            this.onreconnect();
                                        }
                                    });
                                }
                            }
                        }
                    });
                }
            }, delay);
            this.subs.add(new Handle() {
                public void destroy() {
                    timer.cancel();
                }
            });
        }
    }

    /* access modifiers changed from: private */
    public void onreconnect() {
        int attempts = this.backoff.getAttempts();
        this.reconnecting = false;
        this.backoff.reset();
        updateSocketIds();
        emitAll("reconnect", Integer.valueOf(attempts));
    }
}