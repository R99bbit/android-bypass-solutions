package com.ning.http.client.listenable;

import java.util.Queue;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class ExecutionList implements Runnable {
    /* access modifiers changed from: private */
    public static final Logger log = Logger.getLogger(ExecutionList.class.getName());
    private boolean executed = false;
    private final Queue<RunnableExecutorPair> runnables = new LinkedBlockingQueue();

    private static class RunnableExecutorPair {
        final Executor executor;
        final Runnable runnable;

        RunnableExecutorPair(Runnable runnable2, Executor executor2) {
            this.runnable = runnable2;
            this.executor = executor2;
        }

        /* access modifiers changed from: 0000 */
        public void execute() {
            try {
                this.executor.execute(this.runnable);
            } catch (RuntimeException e) {
                ExecutionList.log.log(Level.SEVERE, "RuntimeException while executing runnable " + this.runnable + " with executor " + this.executor, e);
            }
        }
    }

    public void add(Runnable runnable, Executor executor) {
        if (runnable == null) {
            throw new NullPointerException("Runnable is null");
        } else if (executor == null) {
            throw new NullPointerException("Executor is null");
        } else {
            boolean executeImmediate = false;
            synchronized (this.runnables) {
                if (!this.executed) {
                    this.runnables.add(new RunnableExecutorPair(runnable, executor));
                } else {
                    executeImmediate = true;
                }
            }
            if (executeImmediate) {
                executor.execute(runnable);
            }
        }
    }

    public void run() {
        synchronized (this.runnables) {
            this.executed = true;
        }
        while (!this.runnables.isEmpty()) {
            this.runnables.poll().execute();
        }
    }
}