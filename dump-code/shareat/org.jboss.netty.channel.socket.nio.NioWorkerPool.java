package org.jboss.netty.channel.socket.nio;

import java.util.concurrent.Executor;
import org.jboss.netty.util.ThreadNameDeterminer;

public class NioWorkerPool extends AbstractNioWorkerPool<NioWorker> {
    private final ThreadNameDeterminer determiner;

    public NioWorkerPool(Executor workerExecutor, int workerCount) {
        this(workerExecutor, workerCount, null);
    }

    public NioWorkerPool(Executor workerExecutor, int workerCount, ThreadNameDeterminer determiner2) {
        super(workerExecutor, workerCount, false);
        this.determiner = determiner2;
        init();
    }

    /* access modifiers changed from: protected */
    @Deprecated
    public NioWorker createWorker(Executor executor) {
        return new NioWorker(executor, this.determiner);
    }
}