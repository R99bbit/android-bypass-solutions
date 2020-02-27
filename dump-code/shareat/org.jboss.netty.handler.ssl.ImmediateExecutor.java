package org.jboss.netty.handler.ssl;

import java.util.concurrent.Executor;

public final class ImmediateExecutor implements Executor {
    public static final ImmediateExecutor INSTANCE = new ImmediateExecutor();

    public void execute(Runnable command) {
        command.run();
    }

    private ImmediateExecutor() {
    }
}