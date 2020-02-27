package org.jboss.netty.channel;

public class FixedReceiveBufferSizePredictorFactory implements ReceiveBufferSizePredictorFactory {
    private final ReceiveBufferSizePredictor predictor;

    public FixedReceiveBufferSizePredictorFactory(int bufferSize) {
        this.predictor = new FixedReceiveBufferSizePredictor(bufferSize);
    }

    public ReceiveBufferSizePredictor getPredictor() throws Exception {
        return this.predictor;
    }
}