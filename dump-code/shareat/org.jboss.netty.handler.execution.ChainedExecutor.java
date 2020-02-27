package org.jboss.netty.handler.execution;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import org.jboss.netty.util.ExternalResourceReleasable;

public class ChainedExecutor implements Executor, ExternalResourceReleasable {
    static final /* synthetic */ boolean $assertionsDisabled = (!ChainedExecutor.class.desiredAssertionStatus());
    private final Executor cur;
    private final ChannelEventRunnableFilter filter;
    private final Executor next;

    public ChainedExecutor(ChannelEventRunnableFilter filter2, Executor cur2, Executor next2) {
        if (filter2 == null) {
            throw new NullPointerException("filter");
        } else if (cur2 == null) {
            throw new NullPointerException("cur");
        } else if (next2 == null) {
            throw new NullPointerException("next");
        } else {
            this.filter = filter2;
            this.cur = cur2;
            this.next = next2;
        }
    }

    public void execute(Runnable command) {
        if (!$assertionsDisabled && !(command instanceof ChannelEventRunnable)) {
            throw new AssertionError();
        } else if (this.filter.filter((ChannelEventRunnable) command)) {
            this.cur.execute(command);
        } else {
            this.next.execute(command);
        }
    }

    public void releaseExternalResources() {
        if (this.cur instanceof ExecutorService) {
            ((ExecutorService) this.cur).shutdown();
        }
        if (this.next instanceof ExecutorService) {
            ((ExecutorService) this.next).shutdown();
        }
        releaseExternal(this.cur);
        releaseExternal(this.next);
    }

    private static void releaseExternal(Executor executor) {
        if (executor instanceof ExternalResourceReleasable) {
            ((ExternalResourceReleasable) executor).releaseExternalResources();
        }
    }
}