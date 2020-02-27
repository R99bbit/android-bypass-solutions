package com.github.nkzawa.socketio.client;

import com.github.nkzawa.emitter.Emitter;
import com.github.nkzawa.emitter.Emitter.Listener;

public class On {

    public interface Handle {
        void destroy();
    }

    private On() {
    }

    public static Handle on(final Emitter obj, final String ev, final Listener fn) {
        obj.on(ev, fn);
        return new Handle() {
            public void destroy() {
                obj.off(ev, fn);
            }
        };
    }
}