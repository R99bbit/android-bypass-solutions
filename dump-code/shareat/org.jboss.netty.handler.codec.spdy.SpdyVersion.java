package org.jboss.netty.handler.codec.spdy;

public enum SpdyVersion {
    SPDY_3(3, 0, false),
    SPDY_3_1(3, 1, true);
    
    private final int minorVerison;
    private final boolean sessionFlowControl;
    private final int version;

    private SpdyVersion(int version2, int minorVersion, boolean sessionFlowControl2) {
        this.version = version2;
        this.minorVerison = minorVersion;
        this.sessionFlowControl = sessionFlowControl2;
    }

    /* access modifiers changed from: 0000 */
    public int getVersion() {
        return this.version;
    }

    /* access modifiers changed from: 0000 */
    public int getMinorVersion() {
        return this.minorVerison;
    }

    /* access modifiers changed from: 0000 */
    public boolean useSessionFlowControl() {
        return this.sessionFlowControl;
    }
}