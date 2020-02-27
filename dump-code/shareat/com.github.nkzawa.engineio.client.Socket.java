package com.github.nkzawa.engineio.client;

import com.github.nkzawa.emitter.Emitter;
import com.github.nkzawa.emitter.Emitter.Listener;
import com.github.nkzawa.engineio.client.transports.Polling;
import com.github.nkzawa.engineio.client.transports.PollingXHR;
import com.github.nkzawa.engineio.client.transports.WebSocket;
import com.github.nkzawa.engineio.parser.Packet;
import com.github.nkzawa.thread.EventThread;
import com.kakao.util.helper.CommonProtocol;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import org.json.JSONException;

public class Socket extends Emitter {
    public static final String EVENT_CLOSE = "close";
    public static final String EVENT_DATA = "data";
    public static final String EVENT_DRAIN = "drain";
    public static final String EVENT_ERROR = "error";
    public static final String EVENT_FLUSH = "flush";
    public static final String EVENT_HANDSHAKE = "handshake";
    public static final String EVENT_HEARTBEAT = "heartbeat";
    public static final String EVENT_MESSAGE = "message";
    public static final String EVENT_OPEN = "open";
    public static final String EVENT_PACKET = "packet";
    public static final String EVENT_PACKET_CREATE = "packetCreate";
    public static final String EVENT_TRANSPORT = "transport";
    public static final String EVENT_UPGRADE = "upgrade";
    public static final String EVENT_UPGRADE_ERROR = "upgradeError";
    public static final String EVENT_UPGRADING = "upgrading";
    private static HostnameVerifier defaultHostnameVerifier = null;
    private static SSLContext defaultSSLContext = null;
    /* access modifiers changed from: private */
    public static final Logger logger = Logger.getLogger(Socket.class.getName());
    private static final Runnable noop = new Runnable() {
        public void run() {
        }
    };
    /* access modifiers changed from: private */
    public static boolean priorWebsocketSuccess = false;
    public static final int protocol = 3;
    /* access modifiers changed from: private */
    public LinkedList<Runnable> callbackBuffer;
    private ScheduledExecutorService heartbeatScheduler;
    private String hostname;
    private HostnameVerifier hostnameVerifier;
    private String id;
    private final Listener onHeartbeatAsListener;
    private String path;
    private long pingInterval;
    private Future pingIntervalTimer;
    /* access modifiers changed from: private */
    public long pingTimeout;
    private Future pingTimeoutTimer;
    private int policyPort;
    int port;
    /* access modifiers changed from: private */
    public int prevBufferLen;
    private Map<String, String> query;
    /* access modifiers changed from: private */
    public ReadyState readyState;
    /* access modifiers changed from: private */
    public boolean rememberUpgrade;
    private boolean secure;
    private SSLContext sslContext;
    private String timestampParam;
    private boolean timestampRequests;
    Transport transport;
    /* access modifiers changed from: private */
    public List<String> transports;
    private boolean upgrade;
    private List<String> upgrades;
    /* access modifiers changed from: private */
    public boolean upgrading;
    LinkedList<Packet> writeBuffer;

    public static class Options extends com.github.nkzawa.engineio.client.Transport.Options {
        public String host;
        public String query;
        public boolean rememberUpgrade;
        public String[] transports;
        public boolean upgrade = true;

        /* access modifiers changed from: private */
        public static Options fromURI(URI uri, Options opts) {
            if (opts == null) {
                opts = new Options();
            }
            opts.host = uri.getHost();
            opts.secure = CommonProtocol.URL_SCHEME.equals(uri.getScheme()) || "wss".equals(uri.getScheme());
            opts.port = uri.getPort();
            String query2 = uri.getRawQuery();
            if (query2 != null) {
                opts.query = query2;
            }
            return opts;
        }
    }

    private enum ReadyState {
        OPENING,
        OPEN,
        CLOSING,
        CLOSED;

        public String toString() {
            return super.toString().toLowerCase();
        }
    }

    public static void setDefaultSSLContext(SSLContext sslContext2) {
        defaultSSLContext = sslContext2;
    }

    public static void setDefaultHostnameVerifier(HostnameVerifier hostnameVerifier2) {
        defaultHostnameVerifier = hostnameVerifier2;
    }

    public Socket() {
        this(new Options());
    }

    public Socket(String uri) throws URISyntaxException {
        this(uri, (Options) null);
    }

    public Socket(URI uri) {
        this(uri, (Options) null);
    }

    public Socket(String uri, Options opts) throws URISyntaxException {
        this(uri == null ? null : new URI(uri), opts);
    }

    public Socket(URI uri, Options opts) {
        this(uri != null ? Options.fromURI(uri, opts) : opts);
    }

    /*  JADX ERROR: IF instruction can be used only in fallback mode
        jadx.core.utils.exceptions.CodegenException: IF instruction can be used only in fallback mode
        	at jadx.core.codegen.InsnGen.fallbackOnlyInsn(InsnGen.java:571)
        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:477)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:242)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:213)
        	at jadx.core.codegen.RegionGen.makeSimpleBlock(RegionGen.java:109)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:55)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:92)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:58)
        	at jadx.core.codegen.RegionGen.makeRegionIndent(RegionGen.java:98)
        	at jadx.core.codegen.RegionGen.makeIf(RegionGen.java:156)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:62)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:92)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:58)
        	at jadx.core.codegen.MethodGen.addRegionInsns(MethodGen.java:210)
        	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:203)
        	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:315)
        	at jadx.core.codegen.ClassGen.addMethods(ClassGen.java:261)
        	at jadx.core.codegen.ClassGen.addClassBody(ClassGen.java:224)
        	at jadx.core.codegen.ClassGen.addClassCode(ClassGen.java:109)
        	at jadx.core.codegen.ClassGen.makeClass(ClassGen.java:75)
        	at jadx.core.codegen.CodeGen.wrapCodeGen(CodeGen.java:44)
        	at jadx.core.codegen.CodeGen.generateJavaCode(CodeGen.java:32)
        	at jadx.core.codegen.CodeGen.generate(CodeGen.java:20)
        	at jadx.core.ProcessClass.process(ProcessClass.java:36)
        	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
        	at jadx.api.JavaClass.decompile(JavaClass.java:62)
        */
    /* JADX WARNING: Code restructure failed: missing block: B:63:0x011d, code lost:
        r4 = 443;
     */
    public Socket(com.github.nkzawa.engineio.client.Socket.Options r11) {
        /*
            r10 = this;
            r4 = 80
            r9 = 2
            r8 = -1
            r5 = 0
            r6 = 1
            r10.<init>()
            java.util.LinkedList r3 = new java.util.LinkedList
            r3.<init>()
            r10.writeBuffer = r3
            java.util.LinkedList r3 = new java.util.LinkedList
            r3.<init>()
            r10.callbackBuffer = r3
            com.github.nkzawa.engineio.client.Socket$14 r3 = new com.github.nkzawa.engineio.client.Socket$14
            r3.<init>()
            r10.onHeartbeatAsListener = r3
            java.lang.String r3 = r11.host
            if (r3 == 0) goto L_0x004d
            java.lang.String r3 = r11.host
            r7 = 93
            int r3 = r3.indexOf(r7)
            if (r3 == r8) goto L_0x00d1
            r1 = r6
        L_0x002d:
            if (r1 == 0) goto L_0x00d4
            java.lang.String r3 = r11.host
            java.lang.String r7 = "]:"
            java.lang.String[] r2 = r3.split(r7)
        L_0x0038:
            int r3 = r2.length
            if (r3 > r9) goto L_0x0046
            java.lang.String r3 = r11.host
            java.lang.String r7 = "::"
            int r3 = r3.indexOf(r7)
            if (r3 != r8) goto L_0x00df
        L_0x0046:
            r0 = r6
        L_0x0047:
            if (r0 == 0) goto L_0x00e2
            java.lang.String r3 = r11.host
            r11.hostname = r3
        L_0x004d:
            boolean r3 = r11.secure
            r10.secure = r3
            javax.net.ssl.SSLContext r3 = r11.sslContext
            if (r3 == 0) goto L_0x0110
            javax.net.ssl.SSLContext r3 = r11.sslContext
        L_0x0057:
            r10.sslContext = r3
            java.lang.String r3 = r11.hostname
            if (r3 == 0) goto L_0x0114
            java.lang.String r3 = r11.hostname
        L_0x005f:
            r10.hostname = r3
            int r3 = r11.port
            if (r3 == 0) goto L_0x0119
            int r4 = r11.port
        L_0x0067:
            r10.port = r4
            java.lang.String r3 = r11.query
            if (r3 == 0) goto L_0x0121
            java.lang.String r3 = r11.query
            java.util.Map r3 = com.github.nkzawa.parseqs.ParseQS.decode(r3)
        L_0x0073:
            r10.query = r3
            boolean r3 = r11.upgrade
            r10.upgrade = r3
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            r4.<init>()
            java.lang.String r3 = r11.path
            if (r3 == 0) goto L_0x0128
            java.lang.String r3 = r11.path
        L_0x0084:
            java.lang.String r7 = "/$"
            java.lang.String r8 = ""
            java.lang.String r3 = r3.replaceAll(r7, r8)
            java.lang.StringBuilder r3 = r4.append(r3)
            java.lang.String r4 = "/"
            java.lang.StringBuilder r3 = r3.append(r4)
            java.lang.String r3 = r3.toString()
            r10.path = r3
            java.lang.String r3 = r11.timestampParam
            if (r3 == 0) goto L_0x012d
            java.lang.String r3 = r11.timestampParam
        L_0x00a5:
            r10.timestampParam = r3
            boolean r3 = r11.timestampRequests
            r10.timestampRequests = r3
            java.util.ArrayList r4 = new java.util.ArrayList
            java.lang.String[] r3 = r11.transports
            if (r3 == 0) goto L_0x0132
            java.lang.String[] r3 = r11.transports
        L_0x00b3:
            java.util.List r3 = java.util.Arrays.asList(r3)
            r4.<init>(r3)
            r10.transports = r4
            int r3 = r11.policyPort
            if (r3 == 0) goto L_0x0140
            int r3 = r11.policyPort
        L_0x00c2:
            r10.policyPort = r3
            boolean r3 = r11.rememberUpgrade
            r10.rememberUpgrade = r3
            javax.net.ssl.HostnameVerifier r3 = r11.hostnameVerifier
            if (r3 == 0) goto L_0x0143
            javax.net.ssl.HostnameVerifier r3 = r11.hostnameVerifier
        L_0x00ce:
            r10.hostnameVerifier = r3
            return
        L_0x00d1:
            r1 = r5
            goto L_0x002d
        L_0x00d4:
            java.lang.String r3 = r11.host
            java.lang.String r7 = ":"
            java.lang.String[] r2 = r3.split(r7)
            goto L_0x0038
        L_0x00df:
            r0 = r5
            goto L_0x0047
        L_0x00e2:
            r3 = r2[r5]
            r11.hostname = r3
            if (r1 == 0) goto L_0x00f0
            java.lang.String r3 = r11.hostname
            java.lang.String r3 = r3.substring(r6)
            r11.hostname = r3
        L_0x00f0:
            int r3 = r2.length
            if (r3 <= r6) goto L_0x0100
            int r3 = r2.length
            int r3 = r3 + -1
            r3 = r2[r3]
            int r3 = java.lang.Integer.parseInt(r3)
            r11.port = r3
            goto L_0x004d
        L_0x0100:
            int r3 = r11.port
            if (r3 != r8) goto L_0x004d
            boolean r3 = r10.secure
            if (r3 == 0) goto L_0x010e
            r3 = 443(0x1bb, float:6.21E-43)
        L_0x010a:
            r11.port = r3
            goto L_0x004d
        L_0x010e:
            r3 = r4
            goto L_0x010a
        L_0x0110:
            javax.net.ssl.SSLContext r3 = defaultSSLContext
            goto L_0x0057
        L_0x0114:
            java.lang.String r3 = "localhost"
            goto L_0x005f
        L_0x0119:
            boolean r3 = r10.secure
            if (r3 == 0) goto L_0x0067
            r4 = 443(0x1bb, float:6.21E-43)
            goto L_0x0067
        L_0x0121:
            java.util.HashMap r3 = new java.util.HashMap
            r3.<init>()
            goto L_0x0073
        L_0x0128:
            java.lang.String r3 = "/engine.io"
            goto L_0x0084
        L_0x012d:
            java.lang.String r3 = "t"
            goto L_0x00a5
        L_0x0132:
            java.lang.String[] r3 = new java.lang.String[r9]
            java.lang.String r7 = "polling"
            r3[r5] = r7
            java.lang.String r5 = "websocket"
            r3[r6] = r5
            goto L_0x00b3
        L_0x0140:
            r3 = 843(0x34b, float:1.181E-42)
            goto L_0x00c2
        L_0x0143:
            javax.net.ssl.HostnameVerifier r3 = defaultHostnameVerifier
            goto L_0x00ce
        */
        throw new UnsupportedOperationException("Method not decompiled: com.github.nkzawa.engineio.client.Socket.<init>(com.github.nkzawa.engineio.client.Socket$Options):void");
    }

    public Socket open() {
        EventThread.exec(new Runnable() {
            public void run() {
                String transportName;
                if (Socket.this.rememberUpgrade && Socket.priorWebsocketSuccess && Socket.this.transports.contains(WebSocket.NAME)) {
                    transportName = WebSocket.NAME;
                } else if (Socket.this.transports.size() == 0) {
                    final Socket self = Socket.this;
                    EventThread.nextTick(new Runnable() {
                        public void run() {
                            self.emit("error", new EngineIOException((String) "No transports available"));
                        }
                    });
                    return;
                } else {
                    transportName = (String) Socket.this.transports.get(0);
                }
                Socket.this.readyState = ReadyState.OPENING;
                Transport transport = Socket.this.createTransport(transportName);
                Socket.this.setTransport(transport);
                transport.open();
            }
        });
        return this;
    }

    /* access modifiers changed from: private */
    public Transport createTransport(String name) {
        Transport transport2;
        logger.fine(String.format("creating transport '%s'", new Object[]{name}));
        Map<String, String> query2 = new HashMap<>(this.query);
        query2.put("EIO", String.valueOf(3));
        query2.put("transport", name);
        if (this.id != null) {
            query2.put("sid", this.id);
        }
        com.github.nkzawa.engineio.client.Transport.Options opts = new com.github.nkzawa.engineio.client.Transport.Options();
        opts.sslContext = this.sslContext;
        opts.hostname = this.hostname;
        opts.port = this.port;
        opts.secure = this.secure;
        opts.path = this.path;
        opts.query = query2;
        opts.timestampRequests = this.timestampRequests;
        opts.timestampParam = this.timestampParam;
        opts.policyPort = this.policyPort;
        opts.socket = this;
        opts.hostnameVerifier = this.hostnameVerifier;
        if (WebSocket.NAME.equals(name)) {
            transport2 = new WebSocket(opts);
        } else if (Polling.NAME.equals(name)) {
            transport2 = new PollingXHR(opts);
        } else {
            throw new RuntimeException();
        }
        emit("transport", transport2);
        return transport2;
    }

    /* access modifiers changed from: private */
    public void setTransport(Transport transport2) {
        logger.fine(String.format("setting transport %s", new Object[]{transport2.name}));
        if (this.transport != null) {
            logger.fine(String.format("clearing existing transport %s", new Object[]{this.transport.name}));
            this.transport.off();
        }
        this.transport = transport2;
        transport2.on("drain", new Listener() {
            public void call(Object... args) {
                this.onDrain();
            }
        }).on("packet", new Listener() {
            public void call(Object... args) {
                this.onPacket(args.length > 0 ? args[0] : null);
            }
        }).on("error", new Listener() {
            public void call(Object... args) {
                this.onError(args.length > 0 ? args[0] : null);
            }
        }).on("close", new Listener() {
            public void call(Object... args) {
                this.onClose("transport close");
            }
        });
    }

    private void probe(String name) {
        logger.fine(String.format("probing transport '%s'", new Object[]{name}));
        final Transport[] transport2 = {createTransport(name)};
        final boolean[] failed = {false};
        priorWebsocketSuccess = false;
        final String str = name;
        AnonymousClass7 r2 = new Listener() {
            public void call(Object... args) {
                if (!failed[0]) {
                    Socket.logger.fine(String.format("probe transport '%s' opened", new Object[]{str}));
                    Packet<String> packet = new Packet<>(Packet.PING, "probe");
                    transport2[0].send(new Packet[]{packet});
                    transport2[0].once("packet", new Listener() {
                        public void call(Object... args) {
                            if (!failed[0]) {
                                Packet msg = args[0];
                                if (!Packet.PONG.equals(msg.type) || !"probe".equals(msg.data)) {
                                    Socket.logger.fine(String.format("probe transport '%s' failed", new Object[]{str}));
                                    EngineIOException err = new EngineIOException((String) "probe error");
                                    err.transport = transport2[0].name;
                                    this.emit(Socket.EVENT_UPGRADE_ERROR, err);
                                    return;
                                }
                                Socket.logger.fine(String.format("probe transport '%s' pong", new Object[]{str}));
                                this.upgrading = true;
                                this.emit(Socket.EVENT_UPGRADING, transport2[0]);
                                if (transport2[0] != null) {
                                    Socket.priorWebsocketSuccess = WebSocket.NAME.equals(transport2[0].name);
                                    Socket.logger.fine(String.format("pausing current transport '%s'", new Object[]{this.transport.name}));
                                    ((Polling) this.transport).pause(new Runnable() {
                                        public void run() {
                                            if (!failed[0] && ReadyState.CLOSED != this.readyState) {
                                                Socket.logger.fine("changing transport and sending upgrade packet");
                                                cleanup[0].run();
                                                this.setTransport(transport2[0]);
                                                Packet packet = new Packet("upgrade");
                                                transport2[0].send(new Packet[]{packet});
                                                this.emit("upgrade", transport2[0]);
                                                transport2[0] = null;
                                                this.upgrading = false;
                                                this.flush();
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    });
                }
            }
        };
        final Listener freezeTransport = new Listener() {
            public void call(Object... args) {
                if (!failed[0]) {
                    failed[0] = true;
                    cleanup[0].run();
                    transport2[0].close();
                    transport2[0] = null;
                }
            }
        };
        final Transport[] transportArr = transport2;
        final String str2 = name;
        final AnonymousClass9 r9 = new Listener() {
            public void call(Object... args) {
                EngineIOException error;
                Object err = args[0];
                if (err instanceof Exception) {
                    error = new EngineIOException("probe error", (Exception) err);
                } else if (err instanceof String) {
                    error = new EngineIOException("probe error: " + ((String) err));
                } else {
                    error = new EngineIOException((String) "probe error");
                }
                error.transport = transportArr[0].name;
                freezeTransport.call(new Object[0]);
                Socket.logger.fine(String.format("probe transport \"%s\" failed because of error: %s", new Object[]{str2, err}));
                this.emit(Socket.EVENT_UPGRADE_ERROR, error);
            }
        };
        final AnonymousClass10 r0 = new Listener() {
            public void call(Object... args) {
                r9.call("transport closed");
            }
        };
        final AnonymousClass11 r02 = new Listener() {
            public void call(Object... args) {
                r9.call("socket closed");
            }
        };
        final AnonymousClass12 r03 = new Listener() {
            public void call(Object... args) {
                Transport to = args[0];
                if (transport2[0] != null && !to.name.equals(transport2[0].name)) {
                    Socket.logger.fine(String.format("'%s' works - aborting '%s'", new Object[]{to.name, transport2[0].name}));
                    freezeTransport.call(new Object[0]);
                }
            }
        };
        final Transport[] transportArr2 = transport2;
        final AnonymousClass7 r16 = r2;
        final AnonymousClass9 r17 = r9;
        final Runnable[] cleanup = {new Runnable() {
            public void run() {
                transportArr2[0].off("open", r16);
                transportArr2[0].off("error", r17);
                transportArr2[0].off("close", r0);
                this.off("close", r02);
                this.off(Socket.EVENT_UPGRADING, r03);
            }
        }};
        transport2[0].once("open", r2);
        transport2[0].once("error", r9);
        transport2[0].once("close", r0);
        once("close", r02);
        once(EVENT_UPGRADING, r03);
        transport2[0].open();
    }

    private void onOpen() {
        logger.fine("socket open");
        this.readyState = ReadyState.OPEN;
        priorWebsocketSuccess = WebSocket.NAME.equals(this.transport.name);
        emit("open", new Object[0]);
        flush();
        if (this.readyState == ReadyState.OPEN && this.upgrade && (this.transport instanceof Polling)) {
            logger.fine("starting upgrade probes");
            for (String upgrade2 : this.upgrades) {
                probe(upgrade2);
            }
        }
    }

    /* access modifiers changed from: private */
    public void onPacket(Packet packet) {
        if (this.readyState == ReadyState.OPENING || this.readyState == ReadyState.OPEN) {
            logger.fine(String.format("socket received: type '%s', data '%s'", new Object[]{packet.type, packet.data}));
            emit("packet", packet);
            emit(EVENT_HEARTBEAT, new Object[0]);
            if ("open".equals(packet.type)) {
                try {
                    onHandshake(new HandshakeData((String) packet.data));
                } catch (JSONException e) {
                    emit("error", new EngineIOException((Throwable) e));
                }
            } else if (Packet.PONG.equals(packet.type)) {
                setPing();
            } else if ("error".equals(packet.type)) {
                EngineIOException err = new EngineIOException((String) "server error");
                err.code = packet.data;
                emit("error", err);
            } else if ("message".equals(packet.type)) {
                emit("data", packet.data);
                emit("message", packet.data);
            }
        } else {
            logger.fine(String.format("packet received with socket readyState '%s'", new Object[]{this.readyState}));
        }
    }

    private void onHandshake(HandshakeData data) {
        emit(EVENT_HANDSHAKE, data);
        this.id = data.sid;
        this.transport.query.put("sid", data.sid);
        this.upgrades = filterUpgrades(Arrays.asList(data.upgrades));
        this.pingInterval = data.pingInterval;
        this.pingTimeout = data.pingTimeout;
        onOpen();
        if (ReadyState.CLOSED != this.readyState) {
            setPing();
            off(EVENT_HEARTBEAT, this.onHeartbeatAsListener);
            on(EVENT_HEARTBEAT, this.onHeartbeatAsListener);
        }
    }

    /* access modifiers changed from: private */
    public void onHeartbeat(long timeout) {
        if (this.pingTimeoutTimer != null) {
            this.pingTimeoutTimer.cancel(false);
        }
        if (timeout <= 0) {
            timeout = this.pingInterval + this.pingTimeout;
        }
        this.pingTimeoutTimer = getHeartbeatScheduler().schedule(new Runnable() {
            public void run() {
                EventThread.exec(new Runnable() {
                    public void run() {
                        if (this.readyState != ReadyState.CLOSED) {
                            this.onClose("ping timeout");
                        }
                    }
                });
            }
        }, timeout, TimeUnit.MILLISECONDS);
    }

    private void setPing() {
        if (this.pingIntervalTimer != null) {
            this.pingIntervalTimer.cancel(false);
        }
        this.pingIntervalTimer = getHeartbeatScheduler().schedule(new Runnable() {
            public void run() {
                EventThread.exec(new Runnable() {
                    public void run() {
                        Socket.logger.fine(String.format("writing ping packet - expecting pong within %sms", new Object[]{Long.valueOf(this.pingTimeout)}));
                        this.ping();
                        this.onHeartbeat(this.pingTimeout);
                    }
                });
            }
        }, this.pingInterval, TimeUnit.MILLISECONDS);
    }

    public void ping() {
        EventThread.exec(new Runnable() {
            public void run() {
                Socket.this.sendPacket(Packet.PING);
            }
        });
    }

    /* access modifiers changed from: private */
    public void onDrain() {
        for (int i = 0; i < this.prevBufferLen; i++) {
            Runnable callback = this.callbackBuffer.get(i);
            if (callback != null) {
                callback.run();
            }
        }
        for (int i2 = 0; i2 < this.prevBufferLen; i2++) {
            this.writeBuffer.poll();
            this.callbackBuffer.poll();
        }
        this.prevBufferLen = 0;
        if (this.writeBuffer.size() == 0) {
            emit("drain", new Object[0]);
        } else {
            flush();
        }
    }

    /* access modifiers changed from: private */
    public void flush() {
        if (this.readyState != ReadyState.CLOSED && this.transport.writable && !this.upgrading && this.writeBuffer.size() != 0) {
            logger.fine(String.format("flushing %d packets in socket", new Object[]{Integer.valueOf(this.writeBuffer.size())}));
            this.prevBufferLen = this.writeBuffer.size();
            this.transport.send((Packet[]) this.writeBuffer.toArray(new Packet[this.writeBuffer.size()]));
            emit(EVENT_FLUSH, new Object[0]);
        }
    }

    public void write(String msg) {
        write(msg, (Runnable) null);
    }

    public void write(String msg, Runnable fn) {
        send(msg, fn);
    }

    public void write(byte[] msg) {
        write(msg, (Runnable) null);
    }

    public void write(byte[] msg, Runnable fn) {
        send(msg, fn);
    }

    public void send(String msg) {
        send(msg, (Runnable) null);
    }

    public void send(byte[] msg) {
        send(msg, (Runnable) null);
    }

    public void send(final String msg, final Runnable fn) {
        EventThread.exec(new Runnable() {
            public void run() {
                Socket.this.sendPacket((String) "message", msg, fn);
            }
        });
    }

    public void send(final byte[] msg, final Runnable fn) {
        EventThread.exec(new Runnable() {
            public void run() {
                Socket.this.sendPacket((String) "message", msg, fn);
            }
        });
    }

    /* access modifiers changed from: private */
    public void sendPacket(String type) {
        sendPacket(new Packet(type), null);
    }

    /* access modifiers changed from: private */
    public void sendPacket(String type, String data, Runnable fn) {
        sendPacket(new Packet<>(type, data), fn);
    }

    /* access modifiers changed from: private */
    public void sendPacket(String type, byte[] data, Runnable fn) {
        sendPacket(new Packet<>(type, data), fn);
    }

    private void sendPacket(Packet packet, Runnable fn) {
        if (ReadyState.CLOSING != this.readyState && ReadyState.CLOSED != this.readyState) {
            if (fn == null) {
                fn = noop;
            }
            emit(EVENT_PACKET_CREATE, packet);
            this.writeBuffer.offer(packet);
            this.callbackBuffer.offer(fn);
            flush();
        }
    }

    public Socket close() {
        EventThread.exec(new Runnable() {
            public void run() {
                if (Socket.this.readyState == ReadyState.OPENING || Socket.this.readyState == ReadyState.OPEN) {
                    Socket.this.readyState = ReadyState.CLOSING;
                    final Socket self = Socket.this;
                    final Runnable close = new Runnable() {
                        public void run() {
                            self.onClose("forced close");
                            Socket.logger.fine("socket closing - telling transport to close");
                            self.transport.close();
                        }
                    };
                    final Listener[] cleanupAndClose = {new Listener() {
                        public void call(Object... args) {
                            self.off("upgrade", cleanupAndClose[0]);
                            self.off(Socket.EVENT_UPGRADE_ERROR, cleanupAndClose[0]);
                            close.run();
                        }
                    }};
                    final Runnable waitForUpgrade = new Runnable() {
                        public void run() {
                            self.once("upgrade", cleanupAndClose[0]);
                            self.once(Socket.EVENT_UPGRADE_ERROR, cleanupAndClose[0]);
                        }
                    };
                    if (Socket.this.writeBuffer.size() > 0) {
                        Socket.this.once("drain", new Listener() {
                            public void call(Object... args) {
                                if (Socket.this.upgrading) {
                                    waitForUpgrade.run();
                                } else {
                                    close.run();
                                }
                            }
                        });
                    } else if (Socket.this.upgrading) {
                        waitForUpgrade.run();
                    } else {
                        close.run();
                    }
                }
            }
        });
        return this;
    }

    /* access modifiers changed from: private */
    public void onError(Exception err) {
        logger.fine(String.format("socket error %s", new Object[]{err}));
        priorWebsocketSuccess = false;
        emit("error", err);
        onClose("transport error", err);
    }

    /* access modifiers changed from: private */
    public void onClose(String reason) {
        onClose(reason, null);
    }

    private void onClose(String reason, Exception desc) {
        if (ReadyState.OPENING == this.readyState || ReadyState.OPEN == this.readyState || ReadyState.CLOSING == this.readyState) {
            logger.fine(String.format("socket close with reason: %s", new Object[]{reason}));
            if (this.pingIntervalTimer != null) {
                this.pingIntervalTimer.cancel(false);
            }
            if (this.pingTimeoutTimer != null) {
                this.pingTimeoutTimer.cancel(false);
            }
            if (this.heartbeatScheduler != null) {
                this.heartbeatScheduler.shutdown();
            }
            EventThread.nextTick(new Runnable() {
                public void run() {
                    this.writeBuffer.clear();
                    this.callbackBuffer.clear();
                    this.prevBufferLen = 0;
                }
            });
            this.transport.off("close");
            this.transport.close();
            this.transport.off();
            this.readyState = ReadyState.CLOSED;
            this.id = null;
            emit("close", reason, desc);
        }
    }

    /* access modifiers changed from: 0000 */
    public List<String> filterUpgrades(List<String> upgrades2) {
        List<String> filteredUpgrades = new ArrayList<>();
        for (String upgrade2 : upgrades2) {
            if (this.transports.contains(upgrade2)) {
                filteredUpgrades.add(upgrade2);
            }
        }
        return filteredUpgrades;
    }

    public String id() {
        return this.id;
    }

    private ScheduledExecutorService getHeartbeatScheduler() {
        if (this.heartbeatScheduler == null || this.heartbeatScheduler.isShutdown()) {
            this.heartbeatScheduler = Executors.newSingleThreadScheduledExecutor();
        }
        return this.heartbeatScheduler;
    }
}