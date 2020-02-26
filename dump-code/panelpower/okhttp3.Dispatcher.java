package okhttp3;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;
import okhttp3.internal.Util;

public final class Dispatcher {
    @Nullable
    private ExecutorService executorService;
    @Nullable
    private Runnable idleCallback;
    private int maxRequests = 64;
    private int maxRequestsPerHost = 5;
    private final Deque<AsyncCall> readyAsyncCalls = new ArrayDeque();
    private final Deque<AsyncCall> runningAsyncCalls = new ArrayDeque();
    private final Deque<RealCall> runningSyncCalls = new ArrayDeque();

    public Dispatcher(ExecutorService executorService2) {
        this.executorService = executorService2;
    }

    public Dispatcher() {
    }

    public synchronized ExecutorService executorService() {
        if (this.executorService == null) {
            ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(0, Integer.MAX_VALUE, 60, TimeUnit.SECONDS, new SynchronousQueue(), Util.threadFactory("OkHttp Dispatcher", false));
            this.executorService = threadPoolExecutor;
        }
        return this.executorService;
    }

    public synchronized void setMaxRequests(int i) {
        if (i >= 1) {
            this.maxRequests = i;
            promoteCalls();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("max < 1: ");
            sb.append(i);
            throw new IllegalArgumentException(sb.toString());
        }
    }

    public synchronized int getMaxRequests() {
        return this.maxRequests;
    }

    public synchronized void setMaxRequestsPerHost(int i) {
        if (i >= 1) {
            this.maxRequestsPerHost = i;
            promoteCalls();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("max < 1: ");
            sb.append(i);
            throw new IllegalArgumentException(sb.toString());
        }
    }

    public synchronized int getMaxRequestsPerHost() {
        return this.maxRequestsPerHost;
    }

    public synchronized void setIdleCallback(@Nullable Runnable runnable) {
        this.idleCallback = runnable;
    }

    /* access modifiers changed from: 0000 */
    public synchronized void enqueue(AsyncCall asyncCall) {
        if (this.runningAsyncCalls.size() >= this.maxRequests || runningCallsForHost(asyncCall) >= this.maxRequestsPerHost) {
            this.readyAsyncCalls.add(asyncCall);
        } else {
            this.runningAsyncCalls.add(asyncCall);
            executorService().execute(asyncCall);
        }
    }

    public synchronized void cancelAll() {
        for (AsyncCall asyncCall : this.readyAsyncCalls) {
            asyncCall.get().cancel();
        }
        for (AsyncCall asyncCall2 : this.runningAsyncCalls) {
            asyncCall2.get().cancel();
        }
        for (RealCall cancel : this.runningSyncCalls) {
            cancel.cancel();
        }
    }

    private void promoteCalls() {
        if (this.runningAsyncCalls.size() < this.maxRequests && !this.readyAsyncCalls.isEmpty()) {
            Iterator<AsyncCall> it = this.readyAsyncCalls.iterator();
            while (it.hasNext()) {
                AsyncCall next = it.next();
                if (runningCallsForHost(next) < this.maxRequestsPerHost) {
                    it.remove();
                    this.runningAsyncCalls.add(next);
                    executorService().execute(next);
                }
                if (this.runningAsyncCalls.size() >= this.maxRequests) {
                    break;
                }
            }
        }
    }

    private int runningCallsForHost(AsyncCall asyncCall) {
        int i = 0;
        for (AsyncCall next : this.runningAsyncCalls) {
            if (!next.get().forWebSocket && next.host().equals(asyncCall.host())) {
                i++;
            }
        }
        return i;
    }

    /* access modifiers changed from: 0000 */
    public synchronized void executed(RealCall realCall) {
        this.runningSyncCalls.add(realCall);
    }

    /* access modifiers changed from: 0000 */
    public void finished(AsyncCall asyncCall) {
        finished(this.runningAsyncCalls, asyncCall, true);
    }

    /* access modifiers changed from: 0000 */
    public void finished(RealCall realCall) {
        finished(this.runningSyncCalls, realCall, false);
    }

    private <T> void finished(Deque<T> deque, T t, boolean z) {
        int runningCallsCount;
        Runnable runnable;
        synchronized (this) {
            if (deque.remove(t)) {
                if (z) {
                    promoteCalls();
                }
                runningCallsCount = runningCallsCount();
                runnable = this.idleCallback;
            } else {
                throw new AssertionError("Call wasn't in-flight!");
            }
        }
        if (runningCallsCount == 0 && runnable != null) {
            runnable.run();
        }
    }

    public synchronized List<Call> queuedCalls() {
        ArrayList arrayList;
        arrayList = new ArrayList();
        for (AsyncCall asyncCall : this.readyAsyncCalls) {
            arrayList.add(asyncCall.get());
        }
        return Collections.unmodifiableList(arrayList);
    }

    public synchronized List<Call> runningCalls() {
        ArrayList arrayList;
        arrayList = new ArrayList();
        arrayList.addAll(this.runningSyncCalls);
        for (AsyncCall asyncCall : this.runningAsyncCalls) {
            arrayList.add(asyncCall.get());
        }
        return Collections.unmodifiableList(arrayList);
    }

    public synchronized int queuedCallsCount() {
        return this.readyAsyncCalls.size();
    }

    public synchronized int runningCallsCount() {
        return this.runningAsyncCalls.size() + this.runningSyncCalls.size();
    }
}