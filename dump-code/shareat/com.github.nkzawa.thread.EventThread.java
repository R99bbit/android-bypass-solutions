package com.github.nkzawa.thread;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

public class EventThread extends Thread {
    private static final ThreadFactory THREAD_FACTORY = new ThreadFactory() {
        public Thread newThread(Runnable runnable) {
            EventThread.thread = new EventThread(runnable);
            EventThread.thread.setName("EventThread");
            return EventThread.thread;
        }
    };
    /* access modifiers changed from: private */
    public static int counter = 0;
    /* access modifiers changed from: private */
    public static ExecutorService service;
    /* access modifiers changed from: private */
    public static EventThread thread;

    static /* synthetic */ int access$210() {
        int i = counter;
        counter = i - 1;
        return i;
    }

    private EventThread(Runnable runnable) {
        super(runnable);
    }

    public static boolean isCurrent() {
        return currentThread() == thread;
    }

    public static void exec(Runnable task) {
        if (isCurrent()) {
            task.run();
        } else {
            nextTick(task);
        }
    }

    public static void nextTick(final Runnable task) {
        ExecutorService executor;
        synchronized (EventThread.class) {
            counter++;
            if (service == null) {
                service = Executors.newSingleThreadExecutor(THREAD_FACTORY);
            }
            executor = service;
        }
        executor.execute(new Runnable() {
            public void run() {
                try {
                    task.run();
                    synchronized (EventThread.class) {
                        EventThread.access$210();
                        if (EventThread.counter == 0) {
                            EventThread.service.shutdown();
                            EventThread.service = null;
                            EventThread.thread = null;
                        }
                    }
                } catch (Throwable th) {
                    synchronized (EventThread.class) {
                        EventThread.access$210();
                        if (EventThread.counter == 0) {
                            EventThread.service.shutdown();
                            EventThread.service = null;
                            EventThread.thread = null;
                        }
                        throw th;
                    }
                }
            }
        });
    }
}