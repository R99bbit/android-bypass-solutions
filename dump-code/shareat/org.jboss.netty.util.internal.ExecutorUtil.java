package org.jboss.netty.util.internal;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

public final class ExecutorUtil {
    public static void shutdownNow(Executor executor) {
        if (executor instanceof ExecutorService) {
            ExecutorService es = (ExecutorService) executor;
            try {
                es.shutdownNow();
            } catch (SecurityException e) {
                try {
                    es.shutdown();
                } catch (NullPointerException | SecurityException e2) {
                }
            } catch (NullPointerException e3) {
            }
        }
    }

    public static boolean isShutdown(Executor executor) {
        if (!(executor instanceof ExecutorService) || !((ExecutorService) executor).isShutdown()) {
            return false;
        }
        return true;
    }

    public static void terminate(Executor... executors) {
        terminate(DeadLockProofWorker.PARENT, executors);
    }

    public static void terminate(ThreadLocal<Executor> deadLockChecker, Executor... executors) {
        Executor[] arr$;
        if (executors == null) {
            throw new NullPointerException("executors");
        }
        Executor[] executorsCopy = new Executor[executors.length];
        for (int i = 0; i < executors.length; i++) {
            if (executors[i] == null) {
                throw new NullPointerException("executors[" + i + ']');
            }
            executorsCopy[i] = executors[i];
        }
        Executor currentParent = deadLockChecker.get();
        if (currentParent != null) {
            for (Executor e : executorsCopy) {
                if (e == currentParent) {
                    throw new IllegalStateException("An Executor cannot be shut down from the thread acquired from itself.  Please make sure you are not calling releaseExternalResources() from an I/O worker thread.");
                }
            }
        }
        boolean interrupted = false;
        for (Executor e2 : executorsCopy) {
            if (e2 instanceof ExecutorService) {
                ExecutorService es = (ExecutorService) e2;
                while (true) {
                    shutdownNow(es);
                    try {
                        if (es.awaitTermination(100, TimeUnit.MILLISECONDS)) {
                            break;
                        }
                    } catch (InterruptedException e3) {
                        interrupted = true;
                    }
                }
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private ExecutorUtil() {
    }
}