package org.jboss.netty.channel.socket.nio;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.socket.ServerSocketChannel;
import org.jboss.netty.channel.socket.ServerSocketChannelFactory;
import org.jboss.netty.util.ExternalResourceReleasable;

public class NioServerSocketChannelFactory implements ServerSocketChannelFactory {
    private final BossPool<NioServerBoss> bossPool;
    private boolean releasePools;
    private final NioServerSocketPipelineSink sink;
    private final WorkerPool<NioWorker> workerPool;

    public NioServerSocketChannelFactory() {
        this((Executor) Executors.newCachedThreadPool(), (Executor) Executors.newCachedThreadPool());
        this.releasePools = true;
    }

    public NioServerSocketChannelFactory(Executor bossExecutor, Executor workerExecutor) {
        this(bossExecutor, workerExecutor, getMaxThreads(workerExecutor));
    }

    public NioServerSocketChannelFactory(Executor bossExecutor, Executor workerExecutor, int workerCount) {
        this(bossExecutor, 1, workerExecutor, workerCount);
    }

    public NioServerSocketChannelFactory(Executor bossExecutor, int bossCount, Executor workerExecutor, int workerCount) {
        this(bossExecutor, bossCount, (WorkerPool<NioWorker>) new NioWorkerPool<NioWorker>(workerExecutor, workerCount));
    }

    public NioServerSocketChannelFactory(Executor bossExecutor, WorkerPool<NioWorker> workerPool2) {
        this(bossExecutor, 1, workerPool2);
    }

    public NioServerSocketChannelFactory(Executor bossExecutor, int bossCount, WorkerPool<NioWorker> workerPool2) {
        this((BossPool<NioServerBoss>) new NioServerBossPool<NioServerBoss>(bossExecutor, bossCount, null), workerPool2);
    }

    public NioServerSocketChannelFactory(BossPool<NioServerBoss> bossPool2, WorkerPool<NioWorker> workerPool2) {
        if (bossPool2 == null) {
            throw new NullPointerException("bossExecutor");
        } else if (workerPool2 == null) {
            throw new NullPointerException("workerPool");
        } else {
            this.bossPool = bossPool2;
            this.workerPool = workerPool2;
            this.sink = new NioServerSocketPipelineSink();
        }
    }

    public ServerSocketChannel newChannel(ChannelPipeline pipeline) {
        return new NioServerSocketChannel(this, pipeline, this.sink, this.bossPool.nextBoss(), this.workerPool);
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

    private static int getMaxThreads(Executor executor) {
        if (executor instanceof ThreadPoolExecutor) {
            return Math.min(((ThreadPoolExecutor) executor).getMaximumPoolSize(), SelectorUtil.DEFAULT_IO_THREADS);
        }
        return SelectorUtil.DEFAULT_IO_THREADS;
    }
}