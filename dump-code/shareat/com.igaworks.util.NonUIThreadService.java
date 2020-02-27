package com.igaworks.util;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class NonUIThreadService {
    private static final ExecutorService THREADPOOL = Executors.newCachedThreadPool();

    public static void runButNotOn(Runnable toRun, Thread notOn) {
        if (Thread.currentThread() == notOn) {
            THREADPOOL.submit(toRun);
        } else {
            toRun.run();
        }
    }
}