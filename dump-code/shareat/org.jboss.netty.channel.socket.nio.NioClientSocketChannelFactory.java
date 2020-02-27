package org.jboss.netty.channel.socket.nio;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.socket.ClientSocketChannelFactory;
import org.jboss.netty.channel.socket.SocketChannel;
import org.jboss.netty.util.ExternalResourceReleasable;
import org.jboss.netty.util.Timer;

public class NioClientSocketChannelFactory implements ClientSocketChannelFactory {
    private static final int DEFAULT_BOSS_COUNT = 1;
    private final BossPool<NioClientBoss> bossPool;
    private boolean releasePools;
    private final NioClientSocketPipelineSink sink;
    private final WorkerPool<NioWorker> workerPool;

    public NioClientSocketChannelFactory() {
        this((Executor) Executors.newCachedThreadPool(), (Executor) Executors.newCachedThreadPool());
        this.releasePools = true;
    }

    public NioClientSocketChannelFactory(Executor bossExecutor, Executor workerExecutor) {
        this(bossExecutor, workerExecutor, 1, SelectorUtil.DEFAULT_IO_THREADS);
    }

    public NioClientSocketChannelFactory(Executor bossExecutor, Executor workerExecutor, int workerCount) {
        this(bossExecutor, workerExecutor, 1, workerCount);
    }

    public NioClientSocketChannelFactory(Executor bossExecutor, Executor workerExecutor, int bossCount, int workerCount) {
        this(bossExecutor, bossCount, (WorkerPool<NioWorker>) new NioWorkerPool<NioWorker>(workerExecutor, workerCount));
    }

    public NioClientSocketChannelFactory(Executor bossExecutor, int bossCount, WorkerPool<NioWorker> workerPool2) {
        this((BossPool<NioClientBoss>) new NioClientBossPool<NioClientBoss>(bossExecutor, bossCount), workerPool2);
    }

    public NioClientSocketChannelFactory(Executor bossExecutor, int bossCount, WorkerPool<NioWorker> workerPool2, Timer timer) {
        this((BossPool<NioClientBoss>) new NioClientBossPool<NioClientBoss>(bossExecutor, bossCount, timer, null), workerPool2);
    }

    public NioClientSocketChannelFactory(BossPool<NioClientBoss> bossPool2, WorkerPool<NioWorker> workerPool2) {
        if (bossPool2 == null) {
            throw new NullPointerException("bossPool");
        } else if (workerPool2 == null) {
            throw new NullPointerException("workerPool");
        } else {
            this.bossPool = bossPool2;
            this.workerPool = workerPool2;
            this.sink = new NioClientSocketPipelineSink(bossPool2);
        }
    }

    public SocketChannel newChannel(ChannelPipeline pipeline) {
        return new NioClientSocketChannel(this, pipeline, this.sink, (NioWorker) this.workerPool.nextWorker());
    }

    public void shutdown() {
        this.bossPool.shutdown();
        this.workerPool.shutdown();
        if (this.releasePools) {
            releasePools();
        }
    }

    public void releaseExternalResources() {
        shutdown();
        releasePools();
    }

    private void releasePools() {
        if (this.bossPool instanceof ExternalResourceReleasable) {
            ((ExternalResourceReleasable) this.bossPool).releaseExternalResources();
        }
        if (this.workerPool instanceof ExternalResourceReleasable) {
            ((ExternalResourceReleasable) this.workerPool).releaseExternalResources();
        }
    }
}