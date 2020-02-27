package com.igaworks.util.bolts_task;

import java.util.Locale;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

final class BoltsExecutors {
    private static final BoltsExecutors INSTANCE = new BoltsExecutors();
    private final ExecutorService background;
    private final Executor immediate;
    private final ScheduledExecutorService scheduled;

    private static class ImmediateExecutor implements Executor {
        private static final int MAX_DEPTH = 15;
        private ThreadLocal<Integer> executionDepth;

        private ImmediateExecutor() {
            this.executionDepth = new ThreadLocal<>();
        }

        /* synthetic */ ImmediateExecutor(ImmediateExecutor immediateExecutor) {
            this();
        }

        private int incrementDepth() {
            Integer oldDepth = this.executionDepth.get();
            if (oldDepth == null) {
                oldDepth = Integer.valueOf(0);
            }
            int newDepth = oldDepth.intValue() + 1;
            this.executionDepth.set(Integer.valueOf(newDepth));
            return newDepth;
        }

        private int decrementDepth() {
            Integer oldDepth = this.executionDepth.get();
            if (oldDepth == null) {
                oldDepth = Integer.valueOf(0);
            }
            int newDepth = oldDepth.intValue() - 1;
            if (newDepth == 0) {
                this.executionDepth.remove();
            } else {
                this.executionDepth.set(Integer.valueOf(newDepth));
            }
            return newDepth;
        }

        public void execute(Runnable command) {
            if (incrementDepth() <= 15) {
                try {
                    command.run();
                } catch (Throwable th) {
                    decrementDepth();
                    throw th;
                }
            } else {
                BoltsExecutors.background().execute(command);
            }
            decrementDepth();
        }
    }

    private static boolean isAndroidRuntime() {
        String javaRuntimeName = System.getProperty("java.runtime.name");
        if (javaRuntimeName == null) {
            return false;
        }
        return javaRuntimeName.toLowerCase(Locale.US).contains("android");
    }

    private BoltsExecutors() {
        ExecutorService newCachedThreadPool;
        if (!isAndroidRuntime()) {
            newCachedThreadPool = Executors.newCachedThreadPool();
        } else {
            newCachedThreadPool = AndroidExecutors.newCachedThreadPool();
        }
        this.background = newCachedThreadPool;
        this.scheduled = Executors.newSingleThreadScheduledExecutor();
        this.immediate = new ImmediateExecutor(null);
    }

    public static ExecutorService background() {
        return INSTANCE.background;
    }

    static ScheduledExecutorService scheduled() {
        return INSTANCE.scheduled;
    }

    static Executor immediate() {
        return INSTANCE.immediate;
    }
}