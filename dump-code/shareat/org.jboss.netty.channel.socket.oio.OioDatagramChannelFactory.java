package org.jboss.netty.channel.socket.oio;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.socket.DatagramChannel;
import org.jboss.netty.channel.socket.DatagramChannelFactory;
import org.jboss.netty.util.ThreadNameDeterminer;
import org.jboss.netty.util.internal.ExecutorUtil;

public class OioDatagramChannelFactory implements DatagramChannelFactory {
    private boolean shutdownExecutor;
    final OioDatagramPipelineSink sink;
    private final Executor workerExecutor;

    public OioDatagramChannelFactory() {
        this(Executors.newCachedThreadPool());
        this.shutdownExecutor = true;
    }

    public OioDatagramChannelFactory(Executor workerExecutor2) {
        this(workerExecutor2, null);
    }

    public OioDatagramChannelFactory(Executor workerExecutor2, ThreadNameDeterminer determiner) {
        if (workerExecutor2 == null) {
            throw new NullPointerException("workerExecutor");
        }
        this.workerExecutor = workerExecutor2;
        this.sink = new OioDatagramPipelineSink(workerExecutor2, determiner);
    }

    public DatagramChannel newChannel(ChannelPipeline pipeline) {
        return new OioDatagramChannel(this, pipeline, this.sink);
    }

    public void shutdown() {
        if (this.shutdownExecutor) {
            ExecutorUtil.shutdownNow(this.workerExecutor);
        }
    }

    public void releaseExternalResources() {
        shutdown();
        ExecutorUtil.shutdownNow(this.workerExecutor);
    }
}