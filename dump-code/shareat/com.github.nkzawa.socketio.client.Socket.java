package com.github.nkzawa.socketio.client;

import com.github.nkzawa.emitter.Emitter;
import com.github.nkzawa.emitter.Emitter.Listener;
import com.github.nkzawa.hasbinary.HasBinary;
import com.github.nkzawa.socketio.client.On.Handle;
import com.github.nkzawa.socketio.parser.Packet;
import com.github.nkzawa.thread.EventThread;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.logging.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Socket extends Emitter {
    public static final String EVENT_CONNECT = "connect";
    public static final String EVENT_CONNECT_ERROR = "connect_error";
    public static final String EVENT_CONNECT_TIMEOUT = "connect_timeout";
    public static final String EVENT_DISCONNECT = "disconnect";
    public static final String EVENT_ERROR = "error";
    public static final String EVENT_MESSAGE = "message";
    public static final String EVENT_RECONNECT = "reconnect";
    public static final String EVENT_RECONNECTING = "reconnecting";
    public static final String EVENT_RECONNECT_ATTEMPT = "reconnect_attempt";
    public static final String EVENT_RECONNECT_ERROR = "reconnect_error";
    public static final String EVENT_RECONNECT_FAILED = "reconnect_failed";
    protected static Map<String, Integer> events = new HashMap<String, Integer>() {
        {
            put(Socket.EVENT_CONNECT, Integer.valueOf(1));
            put("connect_error", Integer.valueOf(1));
            put("connect_timeout", Integer.valueOf(1));
            put(Socket.EVENT_DISCONNECT, Integer.valueOf(1));
            put("error", Integer.valueOf(1));
            put("reconnect", Integer.valueOf(1));
            put("reconnect_attempt", Integer.valueOf(1));
            put("reconnect_failed", Integer.valueOf(1));
            put("reconnect_error", Integer.valueOf(1));
            put("reconnecting", Integer.valueOf(1));
        }
    };
    /* access modifiers changed from: private */
    public static final Logger logger = Logger.getLogger(Socket.class.getName());
    /* access modifiers changed from: private */
    public Map<Integer, Ack> acks = new HashMap();
    /* access modifiers changed from: private */
    public volatile boolean connected;
    String id;
    /* access modifiers changed from: private */
    public int ids;
    /* access modifiers changed from: private */

    /* renamed from: io reason: collision with root package name */
    public Manager f2io;
    /* access modifiers changed from: private */
    public String nsp;
    private final Queue<List<Object>> receiveBuffer = new LinkedList();
    /* access modifiers changed from: private */
    public final Queue<Packet<JSONArray>> sendBuffer = new LinkedList();
    private Queue<Handle> subs;

    public Socket(Manager io2, String nsp2) {
        this.f2io = io2;
        this.nsp = nsp2;
    }

    /* access modifiers changed from: private */
    public void subEvents() {
        if (this.subs == null) {
            final Manager io2 = this.f2io;
            this.subs = new LinkedList<Handle>() {
                {
                    add(On.on(io2, "open", new Listener() {
                        public void call(Object... args) {
                            Socket.this.onopen();
                        }
                    }));
                    add(On.on(io2, "packet", new Listener() {
                        public void call(Object... args) {
                            Socket.this.onpacket(args[0]);
                        }
                    }));
                    add(On.on(io2, "close", new Listener() {
                        public void call(Object... args) {
                            Socket.this.onclose(args.length > 0 ? args[0] : null);
                        }
                    }));
                }
            };
        }
    }

    public Socket open() {
        EventThread.exec(new Runnable() {
            public void run() {
                if (!Socket.this.connected) {
                    Socket.this.subEvents();
                    Socket.this.f2io.open();
                    if (ReadyState.OPEN == Socket.this.f2io.readyState) {
                        Socket.this.onopen();
                    }
                }
            }
        });
        return this;
    }

    public Socket connect() {
        return open();
    }

    public Socket send(final Object... args) {
        EventThread.exec(new Runnable() {
            public void run() {
                Socket.this.emit("message", args);
            }
        });
        return this;
    }

    public Emitter emit(final String event, final Object... args) {
        EventThread.exec(new Runnable() {
            public void run() {
                if (Socket.events.containsKey(event)) {
                    Socket.super.emit(event, args);
                    return;
                }
                List<Object> _args = new ArrayList<>(args.length + 1);
                _args.add(event);
                _args.addAll(Arrays.asList(args));
                JSONArray jsonArgs = new JSONArray();
                for (Object arg : _args) {
                    jsonArgs.put(arg);
                }
                Packet<JSONArray> packet = new Packet<>(HasBinary.hasBinary(jsonArgs) ? 5 : 2, jsonArgs);
                if (_args.get(_args.size() - 1) instanceof Ack) {
                    Socket.logger.fine(String.format("emitting packet with ack id %d", new Object[]{Integer.valueOf(Socket.this.ids)}));
                    Socket.this.acks.put(Integer.valueOf(Socket.this.ids), (Ack) _args.remove(_args.size() - 1));
                    packet.data = Socket.remove(jsonArgs, jsonArgs.length() - 1);
                    packet.id = Socket.this.ids = Socket.this.ids + 1;
                }
                if (Socket.this.connected) {
                    Socket.this.packet(packet);
                } else {
                    Socket.this.sendBuffer.add(packet);
                }
            }
        });
        return this;
    }

    /* access modifiers changed from: private */
    public static JSONArray remove(JSONArray a, int pos) {
        Object obj;
        JSONArray na = new JSONArray();
        for (int i = 0; i < a.length(); i++) {
            if (i != pos) {
                try {
                    obj = a.get(i);
                } catch (JSONException e) {
                    obj = null;
                }
                na.put(obj);
            }
        }
        return na;
    }

    public Emitter emit(final String event, final Object[] args, final Ack ack) {
        EventThread.exec(new Runnable() {
            public void run() {
                List<Object> _args = new ArrayList<Object>() {
                    {
                        add(event);
                        if (args != null) {
                            addAll(Arrays.asList(args));
                        }
                    }
                };
                JSONArray jsonArgs = new JSONArray();
                for (Object _arg : _args) {
                    jsonArgs.put(_arg);
                }
                Packet<JSONArray> packet = new Packet<>(HasBinary.hasBinary(jsonArgs) ? 5 : 2, jsonArgs);
                Socket.logger.fine(String.format("emitting packet with ack id %d", new Object[]{Integer.valueOf(Socket.this.ids)}));
                Socket.this.acks.put(Integer.valueOf(Socket.this.ids), ack);
                packet.id = Socket.this.ids = Socket.this.ids + 1;
                Socket.this.packet(packet);
            }
        });
        return this;
    }

    /* access modifiers changed from: private */
    public void packet(Packet packet) {
        packet.nsp = this.nsp;
        this.f2io.packet(packet);
    }

    /* access modifiers changed from: private */
    public void onopen() {
        logger.fine("transport is open - connecting");
        if (!"/".equals(this.nsp)) {
            packet(new Packet(0));
        }
    }

    /* access modifiers changed from: private */
    public void onclose(String reason) {
        logger.fine(String.format("close (%s)", new Object[]{reason}));
        this.connected = false;
        this.id = null;
        emit(EVENT_DISCONNECT, reason);
    }

    /* access modifiers changed from: private */
    public void onpacket(Packet packet) {
        if (this.nsp.equals(packet.nsp)) {
            switch (packet.type) {
                case 0:
                    onconnect();
                    return;
                case 1:
                    ondisconnect();
                    return;
                case 2:
                    onevent(packet);
                    return;
                case 3:
                    onack(packet);
                    return;
                case 4:
                    emit("error", packet.data);
                    return;
                case 5:
                    onevent(packet);
                    return;
                case 6:
                    onack(packet);
                    return;
                default:
                    return;
            }
        }
    }

    private void onevent(Packet<JSONArray> packet) {
        List<Object> args = new ArrayList<>(Arrays.asList(toArray((JSONArray) packet.data)));
        logger.fine(String.format("emitting event %s", new Object[]{args}));
        if (packet.id >= 0) {
            logger.fine("attaching ack callback to event");
            args.add(ack(packet.id));
        }
        if (!this.connected) {
            this.receiveBuffer.add(args);
        } else if (args.size() != 0) {
            super.emit(args.remove(0).toString(), args.toArray());
        }
    }

    private Ack ack(final int id2) {
        final boolean[] sent = {false};
        return new Ack() {
            public void call(final Object... args) {
                EventThread.exec(new Runnable() {
                    public void run() {
                        if (!sent[0]) {
                            sent[0] = true;
                            Socket.logger.fine(String.format("sending ack %s", args.length != 0 ? args : null));
                            Packet<JSONArray> packet = new Packet<>(HasBinary.hasBinary(args) ? 6 : 3, new JSONArray(Arrays.asList(args)));
                            packet.id = id2;
                            this.packet(packet);
                        }
                    }
                });
            }
        };
    }

    private void onack(Packet<JSONArray> packet) {
        Ack fn = this.acks.remove(Integer.valueOf(packet.id));
        if (fn != null) {
            logger.fine(String.format("calling ack %s with %s", new Object[]{Integer.valueOf(packet.id), packet.data}));
            fn.call(toArray((JSONArray) packet.data));
            return;
        }
        logger.fine(String.format("bad ack %s", new Object[]{Integer.valueOf(packet.id)}));
    }

    private void onconnect() {
        this.connected = true;
        emit(EVENT_CONNECT, new Object[0]);
        emitBuffered();
    }

    private void emitBuffered() {
        while (true) {
            List<Object> data = this.receiveBuffer.poll();
            if (data == null) {
                break;
            }
            super.emit((String) data.get(0), data.toArray());
        }
        this.receiveBuffer.clear();
        while (true) {
            Packet<JSONArray> packet = this.sendBuffer.poll();
            if (packet != null) {
                packet(packet);
            } else {
                this.sendBuffer.clear();
                return;
            }
        }
    }

    private void ondisconnect() {
        logger.fine(String.format("server disconnect (%s)", new Object[]{this.nsp}));
        destroy();
        onclose("io server disconnect");
    }

    /* access modifiers changed from: private */
    public void destroy() {
        if (this.subs != null) {
            for (Handle sub : this.subs) {
                sub.destroy();
            }
            this.subs = null;
        }
        this.f2io.destroy(this);
    }

    public Socket close() {
        EventThread.exec(new Runnable() {
            public void run() {
                if (Socket.this.connected) {
                    Socket.logger.fine(String.format("performing disconnect (%s)", new Object[]{Socket.this.nsp}));
                    Socket.this.packet(new Packet(1));
                }
                Socket.this.destroy();
                if (Socket.this.connected) {
                    Socket.this.onclose("io client disconnect");
                }
            }
        });
        return this;
    }

    public Socket disconnect() {
        return close();
    }

    public Manager io() {
        return this.f2io;
    }

    public boolean connected() {
        return this.connected;
    }

    public String id() {
        return this.id;
    }

    private static Object[] toArray(JSONArray array) {
        Object obj;
        int length = array.length();
        Object[] data = new Object[length];
        for (int i = 0; i < length; i++) {
            try {
                obj = array.get(i);
            } catch (JSONException e) {
                obj = null;
            }
            if (obj == JSONObject.NULL) {
                obj = null;
            }
            data[i] = obj;
        }
        return data;
    }
}