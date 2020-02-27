package org.jboss.netty.channel;

public class AdaptiveReceiveBufferSizePredictorFactory implements ReceiveBufferSizePredictorFactory {
    private final int initial;
    private final int maximum;
    private final int minimum;

    public AdaptiveReceiveBufferSizePredictorFactory() {
        this(64, 1024, 65536);
    }

    public AdaptiveReceiveBufferSizePredictorFactory(int minimum2, int initial2, int maximum2) {
        if (minimum2 <= 0) {
            throw new IllegalArgumentException("minimum: " + minimum2);
        } else if (initial2 < minimum2) {
            throw new IllegalArgumentException("initial: " + initial2);
        } else if (maximum2 < initial2) {
            throw new IllegalArgumentException("maximum: " + maximum2);
        } else {
            this.minimum = minimum2;
            this.initial = initial2;
            this.maximum = maximum2;
        }
    }

    public ReceiveBufferSizePredictor getPredictor() throws Exception {
        return new AdaptiveReceiveBufferSizePredictor(this.minimum, this.initial, this.maximum);
    }
}