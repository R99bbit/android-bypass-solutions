package org.jboss.netty.handler.codec;

public class PrematureChannelClosureException extends Exception {
    private static final long serialVersionUID = 233460005724966593L;

    public PrematureChannelClosureException() {
    }

    public PrematureChannelClosureException(String msg) {
        super(msg);
    }

    public PrematureChannelClosureException(String msg, Throwable t) {
        super(msg, t);
    }

    public PrematureChannelClosureException(Throwable t) {
        super(t);
    }
}