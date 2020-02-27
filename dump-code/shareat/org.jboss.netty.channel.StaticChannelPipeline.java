package org.jboss.netty.channel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.internal.ConversionUtil;

@Deprecated
public class StaticChannelPipeline implements ChannelPipeline {
    static final InternalLogger logger = InternalLoggerFactory.getInstance(StaticChannelPipeline.class);
    private volatile Channel channel;
    private final StaticChannelHandlerContext[] contexts;
    private final int lastIndex;
    private final Map<String, StaticChannelHandlerContext> name2ctx = new HashMap(4);
    private volatile ChannelSink sink;

    private final class StaticChannelHandlerContext implements ChannelHandlerContext {
        private volatile Object attachment;
        private final boolean canHandleDownstream;
        private final boolean canHandleUpstream;
        private final ChannelHandler handler;
        private final int index;
        private final String name;

        StaticChannelHandlerContext(int index2, String name2, ChannelHandler handler2) {
            if (name2 == null) {
                throw new NullPointerException("name");
            } else if (handler2 == null) {
                throw new NullPointerException("handler");
            } else {
                this.canHandleUpstream = handler2 instanceof ChannelUpstreamHandler;
                this.canHandleDownstream = handler2 instanceof ChannelDownstreamHandler;
                if (this.canHandleUpstream || this.canHandleDownstream) {
                    this.index = index2;
                    this.name = name2;
                    this.handler = handler2;
                    return;
                }
                throw new IllegalArgumentException("handler must be either " + ChannelUpstreamHandler.class.getName() + " or " + ChannelDownstreamHandler.class.getName() + '.');
            }
        }

        public Channel getChannel() {
            return getPipeline().getChannel();
        }

        public ChannelPipeline getPipeline() {
            return StaticChannelPipeline.this;
        }

        public boolean canHandleDownstream() {
            return this.canHandleDownstream;
        }

        public boolean canHandleUpstream() {
            return this.canHandleUpstream;
        }

        public ChannelHandler getHandler() {
            return this.handler;
        }

        public String getName() {
            return this.name;
        }

        public Object getAttachment() {
            return this.attachment;
        }

        public void setAttachment(Object attachment2) {
            this.attachment = attachment2;
        }

        public void sendDownstream(ChannelEvent e) {
            StaticChannelHandlerContext prev = StaticChannelPipeline.this.getActualDownstreamContext(this.index - 1);
            if (prev == null) {
                try {
                    StaticChannelPipeline.this.getSink().eventSunk(StaticChannelPipeline.this, e);
                } catch (Throwable t) {
                    StaticChannelPipeline.this.notifyHandlerException(e, t);
                }
            } else {
                StaticChannelPipeline.this.sendDownstream(prev, e);
            }
        }

        public void sendUpstream(ChannelEvent e) {
            StaticChannelHandlerContext next = StaticChannelPipeline.this.getActualUpstreamContext(this.index + 1);
            if (next != null) {
                StaticChannelPipeline.this.sendUpstream(next, e);
            }
        }
    }

    public StaticChannelPipeline(ChannelHandler... handlers) {
        ChannelHandlerContext[] arr$;
        if (handlers == null) {
            throw new NullPointerException("handlers");
        } else if (handlers.length == 0) {
            throw new IllegalArgumentException("no handlers specified");
        } else {
            StaticChannelHandlerContext[] contexts2 = new StaticChannelHandlerContext[handlers.length];
            int nContexts = 0;
            while (nContexts < contexts2.length && handlers[nContexts] != null) {
                nContexts++;
            }
            if (nContexts == contexts2.length) {
                this.contexts = contexts2;
                this.lastIndex = contexts2.length - 1;
            } else {
                contexts2 = new StaticChannelHandlerContext[nContexts];
                this.contexts = contexts2;
                this.lastIndex = nContexts - 1;
            }
            for (int i = 0; i < nContexts; i++) {
                ChannelHandler h = handlers[i];
                String name = ConversionUtil.toString(i);
                StaticChannelHandlerContext ctx = new StaticChannelHandlerContext(i, name, h);
                contexts2[i] = ctx;
                this.name2ctx.put(name, ctx);
            }
            for (ChannelHandlerContext ctx2 : contexts2) {
                callBeforeAdd(ctx2);
                callAfterAdd(ctx2);
            }
        }
    }

    public ChannelFuture execute(Runnable task) {
        return getSink().execute(this, task);
    }

    public Channel getChannel() {
        return this.channel;
    }

    public ChannelSink getSink() {
        ChannelSink sink2 = this.sink;
        if (sink2 == null) {
            return DefaultChannelPipeline.discardingSink;
        }
        return sink2;
    }

    public void attach(Channel channel2, ChannelSink sink2) {
        if (channel2 == null) {
            throw new NullPointerException("channel");
        } else if (sink2 == null) {
            throw new NullPointerException("sink");
        } else if (this.channel == null && this.sink == null) {
            this.channel = channel2;
            this.sink = sink2;
        } else {
            throw new IllegalStateException("attached already");
        }
    }

    public boolean isAttached() {
        return this.sink != null;
    }

    public void addFirst(String name, ChannelHandler handler) {
        throw new UnsupportedOperationException();
    }

    public void addLast(String name, ChannelHandler handler) {
        throw new UnsupportedOperationException();
    }

    public void addBefore(String baseName, String name, ChannelHandler handler) {
        throw new UnsupportedOperationException();
    }

    public void addAfter(String baseName, String name, ChannelHandler handler) {
        throw new UnsupportedOperationException();
    }

    public void remove(ChannelHandler handler) {
        throw new UnsupportedOperationException();
    }

    public ChannelHandler remove(String name) {
        throw new UnsupportedOperationException();
    }

    public <T extends ChannelHandler> T remove(Class<T> cls) {
        throw new UnsupportedOperationException();
    }

    public ChannelHandler removeFirst() {
        throw new UnsupportedOperationException();
    }

    public ChannelHandler removeLast() {
        throw new UnsupportedOperationException();
    }

    public void replace(ChannelHandler oldHandler, String newName, ChannelHandler newHandler) {
        throw new UnsupportedOperationException();
    }

    public ChannelHandler replace(String oldName, String newName, ChannelHandler newHandler) {
        throw new UnsupportedOperationException();
    }

    public <T extends ChannelHandler> T replace(Class<T> cls, String newName, ChannelHandler newHandler) {
        throw new UnsupportedOperationException();
    }

    private static void callBeforeAdd(ChannelHandlerContext ctx) {
        if (ctx.getHandler() instanceof LifeCycleAwareChannelHandler) {
            LifeCycleAwareChannelHandler h = (LifeCycleAwareChannelHandler) ctx.getHandler();
            try {
                h.beforeAdd(ctx);
            } catch (Throwable t) {
                throw new ChannelHandlerLifeCycleException(h.getClass().getName() + ".beforeAdd() has thrown an exception; not adding.", t);
            }
        }
    }

    private static void callAfterAdd(ChannelHandlerContext ctx) {
        LifeCycleAwareChannelHandler h;
        boolean removed;
        if (ctx.getHandler() instanceof LifeCycleAwareChannelHandler) {
            h = (LifeCycleAwareChannelHandler) ctx.getHandler();
            try {
                h.afterAdd(ctx);
                return;
            } catch (Throwable t2) {
                logger.warn("Failed to remove a handler: " + ctx.getName(), t2);
            }
        } else {
            return;
        }
        if (removed) {
            throw new ChannelHandlerLifeCycleException(h.getClass().getName() + ".afterAdd() has thrown an exception; removed.", t);
        }
        throw new ChannelHandlerLifeCycleException(h.getClass().getName() + ".afterAdd() has thrown an exception; also failed to remove.", t);
    }

    private static void callBeforeRemove(ChannelHandlerContext ctx) {
        if (ctx.getHandler() instanceof LifeCycleAwareChannelHandler) {
            LifeCycleAwareChannelHandler h = (LifeCycleAwareChannelHandler) ctx.getHandler();
            try {
                h.beforeRemove(ctx);
            } catch (Throwable t) {
                throw new ChannelHandlerLifeCycleException(h.getClass().getName() + ".beforeRemove() has thrown an exception; not removing.", t);
            }
        }
    }

    private static void callAfterRemove(ChannelHandlerContext ctx) {
        if (ctx.getHandler() instanceof LifeCycleAwareChannelHandler) {
            LifeCycleAwareChannelHandler h = (LifeCycleAwareChannelHandler) ctx.getHandler();
            try {
                h.afterRemove(ctx);
            } catch (Throwable t) {
                throw new ChannelHandlerLifeCycleException(h.getClass().getName() + ".afterRemove() has thrown an exception.", t);
            }
        }
    }

    public ChannelHandler getFirst() {
        return this.contexts[0].getHandler();
    }

    public ChannelHandler getLast() {
        return this.contexts[this.contexts.length - 1].getHandler();
    }

    public ChannelHandler get(String name) {
        StaticChannelHandlerContext ctx = this.name2ctx.get(name);
        if (ctx == null) {
            return null;
        }
        return ctx.getHandler();
    }

    public <T extends ChannelHandler> T get(Class<T> handlerType) {
        ChannelHandlerContext ctx = getContext(handlerType);
        if (ctx == null) {
            return null;
        }
        return ctx.getHandler();
    }

    public ChannelHandlerContext getContext(String name) {
        if (name != null) {
            return this.name2ctx.get(name);
        }
        throw new NullPointerException("name");
    }

    public ChannelHandlerContext getContext(ChannelHandler handler) {
        StaticChannelHandlerContext[] arr$;
        if (handler == null) {
            throw new NullPointerException("handler");
        }
        for (StaticChannelHandlerContext ctx : this.contexts) {
            if (ctx.getHandler() == handler) {
                return ctx;
            }
        }
        return null;
    }

    public ChannelHandlerContext getContext(Class<? extends ChannelHandler> handlerType) {
        StaticChannelHandlerContext[] arr$;
        if (handlerType == null) {
            throw new NullPointerException("handlerType");
        }
        for (StaticChannelHandlerContext ctx : this.contexts) {
            if (handlerType.isAssignableFrom(ctx.getHandler().getClass())) {
                return ctx;
            }
        }
        return null;
    }

    public List<String> getNames() {
        List<String> list = new ArrayList<>();
        for (StaticChannelHandlerContext ctx : this.contexts) {
            list.add(ctx.getName());
        }
        return list;
    }

    public Map<String, ChannelHandler> toMap() {
        StaticChannelHandlerContext[] arr$;
        Map<String, ChannelHandler> map = new LinkedHashMap<>();
        for (StaticChannelHandlerContext ctx : this.contexts) {
            map.put(ctx.getName(), ctx.getHandler());
        }
        return map;
    }

    public String toString() {
        StaticChannelHandlerContext[] arr$;
        StringBuilder buf = new StringBuilder();
        buf.append(getClass().getSimpleName());
        buf.append('{');
        for (StaticChannelHandlerContext ctx : this.contexts) {
            buf.append('(');
            buf.append(ctx.getName());
            buf.append(" = ");
            buf.append(ctx.getHandler().getClass().getName());
            buf.append(')');
            buf.append(", ");
        }
        buf.replace(buf.length() - 2, buf.length(), "}");
        return buf.toString();
    }

    public void sendUpstream(ChannelEvent e) {
        StaticChannelHandlerContext head = getActualUpstreamContext(0);
        if (head == null) {
            logger.warn("The pipeline contains no upstream handlers; discarding: " + e);
        } else {
            sendUpstream(head, e);
        }
    }

    /* access modifiers changed from: 0000 */
    public void sendUpstream(StaticChannelHandlerContext ctx, ChannelEvent e) {
        try {
            ((ChannelUpstreamHandler) ctx.getHandler()).handleUpstream(ctx, e);
        } catch (Throwable t) {
            notifyHandlerException(e, t);
        }
    }

    public void sendDownstream(ChannelEvent e) {
        StaticChannelHandlerContext tail = getActualDownstreamContext(this.lastIndex);
        if (tail == null) {
            try {
                getSink().eventSunk(this, e);
            } catch (Throwable t) {
                notifyHandlerException(e, t);
            }
        } else {
            sendDownstream(tail, e);
        }
    }

    /* access modifiers changed from: 0000 */
    public void sendDownstream(StaticChannelHandlerContext ctx, ChannelEvent e) {
        if (e instanceof UpstreamMessageEvent) {
            throw new IllegalArgumentException("cannot send an upstream event to downstream");
        }
        try {
            ((ChannelDownstreamHandler) ctx.getHandler()).handleDownstream(ctx, e);
        } catch (Throwable t) {
            e.getFuture().setFailure(t);
            notifyHandlerException(e, t);
        }
    }

    /* access modifiers changed from: private */
    public StaticChannelHandlerContext getActualUpstreamContext(int index) {
        for (int i = index; i < this.contexts.length; i++) {
            StaticChannelHandlerContext ctx = this.contexts[i];
            if (ctx.canHandleUpstream()) {
                return ctx;
            }
        }
        return null;
    }

    /* access modifiers changed from: private */
    public StaticChannelHandlerContext getActualDownstreamContext(int index) {
        for (int i = index; i >= 0; i--) {
            StaticChannelHandlerContext ctx = this.contexts[i];
            if (ctx.canHandleDownstream()) {
                return ctx;
            }
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public void notifyHandlerException(ChannelEvent e, Throwable t) {
        ChannelPipelineException pe;
        if (e instanceof ExceptionEvent) {
            logger.warn("An exception was thrown by a user handler while handling an exception event (" + e + ')', t);
            return;
        }
        if (t instanceof ChannelPipelineException) {
            pe = (ChannelPipelineException) t;
        } else {
            pe = new ChannelPipelineException(t);
        }
        try {
            this.sink.exceptionCaught(this, e, pe);
        } catch (Exception e1) {
            logger.warn("An exception was thrown by an exception handler.", e1);
        }
    }
}