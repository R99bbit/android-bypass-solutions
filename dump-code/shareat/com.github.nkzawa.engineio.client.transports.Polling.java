package com.github.nkzawa.engineio.client.transports;

import com.github.nkzawa.emitter.Emitter.Listener;
import com.github.nkzawa.engineio.client.Transport;
import com.github.nkzawa.engineio.client.Transport.Options;
import com.github.nkzawa.engineio.parser.Packet;
import com.github.nkzawa.engineio.parser.Parser;
import com.github.nkzawa.engineio.parser.Parser.DecodePayloadCallback;
import com.github.nkzawa.engineio.parser.Parser.EncodeCallback;
import com.github.nkzawa.parseqs.ParseQS;
import com.github.nkzawa.thread.EventThread;
import com.kakao.util.helper.CommonProtocol;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public abstract class Polling extends Transport {
    public static final String EVENT_POLL = "poll";
    public static final String EVENT_POLL_COMPLETE = "pollComplete";
    public static final String NAME = "polling";
    /* access modifiers changed from: private */
    public static final Logger logger = Logger.getLogger(Polling.class.getName());
    /* access modifiers changed from: private */
    public boolean polling;

    /* access modifiers changed from: protected */
    public abstract void doPoll();

    /* access modifiers changed from: protected */
    public abstract void doWrite(byte[] bArr, Runnable runnable);

    public Polling(Options opts) {
        super(opts);
        this.name = NAME;
    }

    /* access modifiers changed from: protected */
    public void doOpen() {
        poll();
    }

    public void pause(final Runnable onPause) {
        EventThread.exec(new Runnable() {
            public void run() {
                final Polling self = Polling.this;
                Polling.this.readyState = ReadyState.PAUSED;
                final Runnable pause = new Runnable() {
                    public void run() {
                        Polling.logger.fine("paused");
                        self.readyState = ReadyState.PAUSED;
                        onPause.run();
                    }
                };
                if (Polling.this.polling || !Polling.this.writable) {
                    final int[] total = {0};
                    if (Polling.this.polling) {
                        Polling.logger.fine("we are currently polling - waiting to pause");
                        total[0] = total[0] + 1;
                        Polling.this.once(Polling.EVENT_POLL_COMPLETE, new Listener() {
                            public void call(Object... args) {
                                Polling.logger.fine("pre-pause polling complete");
                                int[] iArr = total;
                                int i = iArr[0] - 1;
                                iArr[0] = i;
                                if (i == 0) {
                                    pause.run();
                                }
                            }
                        });
                    }
                    if (!Polling.this.writable) {
                        Polling.logger.fine("we are currently writing - waiting to pause");
                        total[0] = total[0] + 1;
                        Polling.this.once("drain", new Listener() {
                            public void call(Object... args) {
                                Polling.logger.fine("pre-pause writing complete");
                                int[] iArr = total;
                                int i = iArr[0] - 1;
                                iArr[0] = i;
                                if (i == 0) {
                                    pause.run();
                                }
                            }
                        });
                        return;
                    }
                    return;
                }
                pause.run();
            }
        });
    }

    private void poll() {
        logger.fine(NAME);
        this.polling = true;
        doPoll();
        emit(EVENT_POLL, new Object[0]);
    }

    /* access modifiers changed from: protected */
    public void onData(String data) {
        _onData(data);
    }

    /* access modifiers changed from: protected */
    public void onData(byte[] data) {
        _onData(data);
    }

    private void _onData(Object data) {
        logger.fine(String.format("polling got data %s", new Object[]{data}));
        DecodePayloadCallback<String> _callback = new DecodePayloadCallback() {
            public boolean call(Packet packet, int index, int total) {
                if (this.readyState == ReadyState.OPENING) {
                    this.onOpen();
                }
                if ("close".equals(packet.type)) {
                    this.onClose();
                    return false;
                }
                this.onPacket(packet);
                return true;
            }
        };
        if (data instanceof String) {
            Parser.decodePayload((String) data, _callback);
        } else if (data instanceof byte[]) {
            Parser.decodePayload((byte[]) (byte[]) data, (DecodePayloadCallback) _callback);
        }
        if (this.readyState != ReadyState.CLOSED) {
            this.polling = false;
            emit(EVENT_POLL_COMPLETE, new Object[0]);
            if (this.readyState == ReadyState.OPEN) {
                poll();
                return;
            }
            logger.fine(String.format("ignoring poll - transport state '%s'", new Object[]{this.readyState}));
        }
    }

    /* access modifiers changed from: protected */
    public void doClose() {
        Listener close = new Listener() {
            public void call(Object... args) {
                Polling.logger.fine("writing close packet");
                this.write(new Packet[]{new Packet("close")});
            }
        };
        if (this.readyState == ReadyState.OPEN) {
            logger.fine("transport open - closing");
            close.call(new Object[0]);
            return;
        }
        logger.fine("transport not open - deferring close");
        once("open", close);
    }

    /* access modifiers changed from: protected */
    public void write(Packet[] packets) {
        this.writable = false;
        final Runnable callbackfn = new Runnable() {
            public void run() {
                this.writable = true;
                this.emit("drain", new Object[0]);
            }
        };
        Parser.encodePayload(packets, new EncodeCallback<byte[]>() {
            public void call(byte[] data) {
                this.doWrite(data, callbackfn);
            }
        });
    }

    /* access modifiers changed from: protected */
    public String uri() {
        Map<String, String> query = this.query;
        if (query == null) {
            query = new HashMap<>();
        }
        String schema = this.secure ? CommonProtocol.URL_SCHEME : "http";
        String port = "";
        if (this.timestampRequests) {
            String str = this.timestampParam;
            StringBuilder append = new StringBuilder().append(String.valueOf(new Date().getTime())).append("-");
            int i = Transport.timestamps;
            Transport.timestamps = i + 1;
            query.put(str, append.append(i).toString());
        }
        String _query = ParseQS.encode(query);
        if (this.port > 0 && ((CommonProtocol.URL_SCHEME.equals(schema) && this.port != 443) || ("http".equals(schema) && this.port != 80))) {
            port = ":" + this.port;
        }
        if (_query.length() > 0) {
            _query = "?" + _query;
        }
        return schema + "://" + this.hostname + port + this.path + _query;
    }
}