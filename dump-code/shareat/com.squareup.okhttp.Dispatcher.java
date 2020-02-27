package com.squareup.okhttp;

import com.squareup.okhttp.internal.Util;
import com.squareup.okhttp.internal.http.HttpEngine;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public final class Dispatcher {
    private final Deque<Call> executedCalls = new ArrayDeque();
    private ExecutorService executorService;
    private int maxRequests = 64;
    private int maxRequestsPerHost = 5;
    private final Deque<AsyncCall> readyCalls = new ArrayDeque();
    private final Deque<AsyncCall> runningCalls = new ArrayDeque();

    public Dispatcher(ExecutorService executorService2) {
        this.executorService = executorService2;
    }

    public Dispatcher() {
    }

    public synchronized ExecutorService getExecutorService() {
        try {
            if (this.executorService == null) {
                this.executorService = new ThreadPoolExecutor(0, ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED, 60, TimeUnit.SECONDS, new SynchronousQueue(), Util.threadFactory("OkHttp Dispatcher", false));
            }
        }
        return this.executorService;
    }

    public synchronized void setMaxRequests(int maxRequests2) {
        if (maxRequests2 < 1) {
            throw new IllegalArgumentException("max < 1: " + maxRequests2);
        }
        this.maxRequests = maxRequests2;
        promoteCalls();
    }

    public synchronized int getMaxRequests() {
        return this.maxRequests;
    }

    public synchronized void setMaxRequestsPerHost(int maxRequestsPerHost2) {
        if (maxRequestsPerHost2 < 1) {
            throw new IllegalArgumentException("max < 1: " + maxRequestsPerHost2);
        }
        this.maxRequestsPerHost = maxRequestsPerHost2;
        promoteCalls();
    }

    public synchronized int getMaxRequestsPerHost() {
        return this.maxRequestsPerHost;
    }

    /* access modifiers changed from: 0000 */
    public synchronized void enqueue(AsyncCall call) {
        if (this.runningCalls.size() >= this.maxRequests || runningCallsForHost(call) >= this.maxRequestsPerHost) {
            this.readyCalls.add(call);
        } else {
            this.runningCalls.add(call);
            getExecutorService().execute(call);
        }
    }

    public synchronized void cancel(Object tag) {
        for (AsyncCall call : this.readyCalls) {
            if (Util.equal(tag, call.tag())) {
                call.cancel();
            }
        }
        for (AsyncCall call2 : this.runningCalls) {
            if (Util.equal(tag, call2.tag())) {
                call2.get().canceled = true;
                HttpEngine engine = call2.get().engine;
                if (engine != null) {
                    engine.disconnect();
                }
            }
        }
        for (Call call3 : this.executedCalls) {
            if (Util.equal(tag, call3.tag())) {
                call3.cancel();
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public synchronized void finished(AsyncCall call) {
        if (!this.runningCalls.remove(call)) {
            throw new AssertionError("AsyncCall wasn't running!");
        }
        promoteCalls();
    }

    private void promoteCalls() {
        if (this.runningCalls.size() < this.maxRequests && !this.readyCalls.isEmpty()) {
            Iterator<AsyncCall> it = this.readyCalls.iterator();
            while (it.hasNext()) {
                AsyncCall call = it.next();
                if (runningCallsForHost(call) < this.maxRequestsPerHost) {
                    it.remove();
                    this.runningCalls.add(call);
                    getExecutorService().execute(call);
                }
                if (this.runningCalls.size() >= this.maxRequests) {
                    return;
                }
            }
        }
    }

    private int runningCallsForHost(AsyncCall call) {
        int result = 0;
        for (AsyncCall c : this.runningCalls) {
            if (c.host().equals(call.host())) {
                result++;
            }
        }
        return result;
    }

    /* access modifiers changed from: 0000 */
    public synchronized void executed(Call call) {
        this.executedCalls.add(call);
    }

    /* access modifiers changed from: 0000 */
    public synchronized void finished(Call call) {
        if (!this.executedCalls.remove(call)) {
            throw new AssertionError("Call wasn't in-flight!");
        }
    }

    public synchronized int getRunningCallCount() {
        return this.runningCalls.size();
    }

    public synchronized int getQueuedCallCount() {
        return this.readyCalls.size();
    }
}