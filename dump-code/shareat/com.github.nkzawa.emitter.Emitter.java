package com.github.nkzawa.emitter;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;

public class Emitter {
    private ConcurrentMap<String, ConcurrentLinkedQueue<Listener>> callbacks = new ConcurrentHashMap();

    public interface Listener {
        void call(Object... objArr);
    }

    private class OnceListener implements Listener {
        public final String event;
        public final Listener fn;

        public OnceListener(String event2, Listener fn2) {
            this.event = event2;
            this.fn = fn2;
        }

        public void call(Object... args) {
            Emitter.this.off(this.event, this);
            this.fn.call(args);
        }
    }

    public Emitter on(String event, Listener fn) {
        ConcurrentLinkedQueue<Listener> callbacks2 = (ConcurrentLinkedQueue) this.callbacks.get(event);
        if (callbacks2 == null) {
            callbacks2 = new ConcurrentLinkedQueue<>();
            ConcurrentLinkedQueue<Listener> _callbacks = this.callbacks.putIfAbsent(event, callbacks2);
            if (_callbacks != null) {
                callbacks2 = _callbacks;
            }
        }
        callbacks2.add(fn);
        return this;
    }

    public Emitter once(String event, Listener fn) {
        on(event, new OnceListener(event, fn));
        return this;
    }

    public Emitter off() {
        this.callbacks.clear();
        return this;
    }

    public Emitter off(String event) {
        this.callbacks.remove(event);
        return this;
    }

    public Emitter off(String event, Listener fn) {
        ConcurrentLinkedQueue<Listener> callbacks2 = (ConcurrentLinkedQueue) this.callbacks.get(event);
        if (callbacks2 != null) {
            Iterator<Listener> it = callbacks2.iterator();
            while (true) {
                if (it.hasNext()) {
                    if (sameAs(fn, it.next())) {
                        it.remove();
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        return this;
    }

    private static boolean sameAs(Listener fn, Listener internal) {
        if (fn.equals(internal)) {
            return true;
        }
        if (internal instanceof OnceListener) {
            return fn.equals(((OnceListener) internal).fn);
        }
        return false;
    }

    public Emitter emit(String event, Object... args) {
        ConcurrentLinkedQueue<Listener> callbacks2 = (ConcurrentLinkedQueue) this.callbacks.get(event);
        if (callbacks2 != null) {
            Iterator i$ = callbacks2.iterator();
            while (i$.hasNext()) {
                i$.next().call(args);
            }
        }
        return this;
    }

    public List<Listener> listeners(String event) {
        ConcurrentLinkedQueue<Listener> callbacks2 = (ConcurrentLinkedQueue) this.callbacks.get(event);
        return callbacks2 != null ? new ArrayList(callbacks2) : new ArrayList(0);
    }

    public boolean hasListeners(String event) {
        ConcurrentLinkedQueue<Listener> callbacks2 = (ConcurrentLinkedQueue) this.callbacks.get(event);
        return callbacks2 != null && !callbacks2.isEmpty();
    }
}