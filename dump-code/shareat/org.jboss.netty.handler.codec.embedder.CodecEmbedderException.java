package org.jboss.netty.handler.codec.embedder;

public class CodecEmbedderException extends RuntimeException {
    private static final long serialVersionUID = -6283302594160331474L;

    public CodecEmbedderException() {
    }

    public CodecEmbedderException(String message, Throwable cause) {
        super(message, cause);
    }

    public CodecEmbedderException(String message) {
        super(message);
    }

    public CodecEmbedderException(Throwable cause) {
        super(cause);
    }
}