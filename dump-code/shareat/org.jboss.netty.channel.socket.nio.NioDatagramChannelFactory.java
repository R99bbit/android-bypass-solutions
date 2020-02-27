package org.jboss.netty.channel.socket.nio;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.socket.DatagramChannel;
import org.jboss.netty.channel.socket.DatagramChannelFactory;
import org.jboss.netty.channel.socket.InternetProtocolFamily;
import org.jboss.netty.util.ExternalResourceReleasable;

public class NioDatagramChannelFactory implements DatagramChannelFactory {
    private final InternetProtocolFamily family;
    private boolean releasePool;
    private final NioDatagramPipelineSink sink;
    private final WorkerPool<NioDatagramWorker> workerPool;

    public NioDatagramChannelFactory() {
        this((InternetProtocolFamily) null);
    }

    public NioDatagramChannelFactory(InternetProtocolFamily family2) {
        this.workerPool = new NioDatagramWorkerPool(Executors.newCachedThreadPool(), SelectorUtil.DEFAULT_IO_THREADS);
        this.family = family2;
        this.sink = new NioDatagramPipelineSink(this.workerPool);
        this.releasePool = true;
    }

    public NioDatagramChannelFactory(Executor workerExecutor) {
        this(workerExecutor, SelectorUtil.DEFAULT_IO_THREADS);
    }

    public NioDatagramChannelFactory(Executor workerExecutor, int workerCount) {
        this((WorkerPool<NioDatagramWorker>) new NioDatagramWorkerPool<NioDatagramWorker>(workerExecutor, workerCount));
    }

    public NioDatagramChannelFactory(WorkerPool<NioDatagramWorker> workerPool2) {
        this(workerPool2, (InternetProtocolFamily) null);
    }

    public NioDatagramChannelFactory(Executor workerExecutor, InternetProtocolFamily family2) {
        this(workerExecutor, SelectorUtil.DEFAULT_IO_THREADS, family2);
    }

    public NioDatagramChannelFactory(Executor workerExecutor, int workerCount, InternetProtocolFamily family2) {
        this((WorkerPool<NioDatagramWorker>) new NioDatagramWorkerPool<NioDatagramWorker>(workerExecutor, workerCount), family2);
    }

    public NioDatagramChannelFactory(WorkerPool<NioDatagramWorker> workerPool2, InternetProtocolFamily family2) {
        this.workerPool = workerPool2;
        this.family = family2;
        this.sink = new NioDatagramPipelineSink(workerPool2);
    }

    public DatagramChannel newChannel(ChannelPipeline pipeline) {
        return new NioDatagramChannel(this, pipeline, this.sink, this.sink.nextWorker(), this.family);
    }

    public void shutdown() {
        this.workerPool.shutdown();
        if (this.releasePool) {
            releasePool();
        }
    }

    public void releaseExternalResources() {
        shutdown();
        releasePool();
    }

    private void releasePool() {
        if (this.workerPool instanceof ExternalResourceReleasable) {
            ((ExternalResourceReleasable) this.workerPool).releaseExternalResources();
        }
    }
}