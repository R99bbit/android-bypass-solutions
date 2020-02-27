package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.net.ConnectException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.ConnectTimeoutException;
import org.jboss.netty.util.ThreadNameDeterminer;
import org.jboss.netty.util.ThreadRenamingRunnable;
import org.jboss.netty.util.Timeout;
import org.jboss.netty.util.Timer;
import org.jboss.netty.util.TimerTask;

public final class NioClientBoss extends AbstractNioSelector implements Boss {
    /* access modifiers changed from: private */
    public final Timer timer;
    /* access modifiers changed from: private */
    public final TimerTask wakeupTask = new TimerTask() {
        public void run(Timeout timeout) throws Exception {
            Selector selector = NioClientBoss.this.selector;
            if (selector != null && NioClientBoss.this.wakenUp.compareAndSet(false, true)) {
                selector.wakeup();
            }
        }
    };

    private final class RegisterTask implements Runnable {
        private final NioClientBoss boss;
        private final NioClientSocketChannel channel;

        RegisterTask(NioClientBoss boss2, NioClientSocketChannel channel2) {
            this.boss = boss2;
            this.channel = channel2;
        }

        public void run() {
            int timeout = this.channel.getConfig().getConnectTimeoutMillis();
            if (timeout > 0 && !this.channel.isConnected()) {
                this.channel.timoutTimer = NioClientBoss.this.timer.newTimeout(NioClientBoss.this.wakeupTask, (long) timeout, TimeUnit.MILLISECONDS);
            }
            try {
                ((SocketChannel) this.channel.channel).register(this.boss.selector, 8, this.channel);
            } catch (ClosedChannelException e) {
                this.channel.worker.close(this.channel, Channels.succeededFuture(this.channel));
            }
            int connectTimeout = this.channel.getConfig().getConnectTimeoutMillis();
            if (connectTimeout > 0) {
                this.channel.connectDeadlineNanos = System.nanoTime() + (((long) connectTimeout) * 1000000);
            }
        }
    }

    public /* bridge */ /* synthetic */ void rebuildSelector() {
        super.rebuildSelector();
    }

    public /* bridge */ /* synthetic */ void register(Channel x0, ChannelFuture x1) {
        super.register(x0, x1);
    }

    public /* bridge */ /* synthetic */ void run() {
        super.run();
    }

    public /* bridge */ /* synthetic */ void shutdown() {
        super.shutdown();
    }

    NioClientBoss(Executor bossExecutor, Timer timer2, ThreadNameDeterminer determiner) {
        super(bossExecutor, determiner);
        this.timer = timer2;
    }

    /* access modifiers changed from: protected */
    public ThreadRenamingRunnable newThreadRenamingRunnable(int id, ThreadNameDeterminer determiner) {
        return new ThreadRenamingRunnable(this, "New I/O boss #" + id, determiner);
    }

    /* access modifiers changed from: protected */
    public Runnable createRegisterTask(Channel channel, ChannelFuture future) {
        return new RegisterTask(this, (NioClientSocketChannel) channel);
    }

    /* access modifiers changed from: protected */
    public void process(Selector selector) {
        processSelectedKeys(selector.selectedKeys());
        processConnectTimeout(selector.keys(), System.nanoTime());
    }

    private void processSelectedKeys(Set<SelectionKey> selectedKeys) {
        if (!selectedKeys.isEmpty()) {
            Iterator<SelectionKey> it = selectedKeys.iterator();
            while (it.hasNext()) {
                SelectionKey k = it.next();
                it.remove();
                if (!k.isValid()) {
                    close(k);
                } else {
                    try {
                        if (k.isConnectable()) {
                            connect(k);
                        }
                    } catch (Throwable t) {
                        NioClientSocketChannel ch = (NioClientSocketChannel) k.attachment();
                        ch.connectFuture.setFailure(t);
                        Channels.fireExceptionCaught((Channel) ch, t);
                        k.cancel();
                        ch.worker.close(ch, Channels.succeededFuture(ch));
                    }
                }
            }
        }
    }

    private static void processConnectTimeout(Set<SelectionKey> keys, long currentTimeNanos) {
        ConnectException cause = null;
        for (SelectionKey k : keys) {
            if (k.isValid()) {
                NioClientSocketChannel ch = (NioClientSocketChannel) k.attachment();
                if (ch.connectDeadlineNanos > 0 && currentTimeNanos >= ch.connectDeadlineNanos) {
                    if (cause == null) {
                        cause = new ConnectTimeoutException("connection timed out: " + ch.requestedRemoteAddress);
                    }
                    ch.connectFuture.setFailure(cause);
                    Channels.fireExceptionCaught((Channel) ch, (Throwable) cause);
                    ch.worker.close(ch, Channels.succeededFuture(ch));
                }
            }
        }
    }

    private static void connect(SelectionKey k) throws IOException {
        NioClientSocketChannel ch = (NioClientSocketChannel) k.attachment();
        try {
            if (((SocketChannel) ch.channel).finishConnect()) {
                k.cancel();
                if (ch.timoutTimer != null) {
                    ch.timoutTimer.cancel();
                }
                ch.worker.register(ch, ch.connectFuture);
            }
        } catch (ConnectException e) {
            ConnectException newE = new ConnectException(e.getMessage() + ": " + ch.requestedRemoteAddress);
            newE.setStackTrace(e.getStackTrace());
            throw newE;
        }
    }

    /* access modifiers changed from: protected */
    public void close(SelectionKey k) {
        NioClientSocketChannel ch = (NioClientSocketChannel) k.attachment();
        ch.worker.close(ch, Channels.succeededFuture(ch));
    }
}