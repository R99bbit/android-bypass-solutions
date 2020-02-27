package org.jboss.netty.channel;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

public class DefaultFileRegion implements FileRegion {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(DefaultFileRegion.class);
    private final long count;
    private final FileChannel file;
    private final long position;
    private final boolean releaseAfterTransfer;

    public DefaultFileRegion(FileChannel file2, long position2, long count2) {
        this(file2, position2, count2, false);
    }

    public DefaultFileRegion(FileChannel file2, long position2, long count2, boolean releaseAfterTransfer2) {
        this.file = file2;
        this.position = position2;
        this.count = count2;
        this.releaseAfterTransfer = releaseAfterTransfer2;
    }

    public long getPosition() {
        return this.position;
    }

    public long getCount() {
        return this.count;
    }

    public boolean releaseAfterTransfer() {
        return this.releaseAfterTransfer;
    }

    public long transferTo(WritableByteChannel target, long position2) throws IOException {
        long count2 = this.count - position2;
        if (count2 < 0 || position2 < 0) {
            throw new IllegalArgumentException("position out of range: " + position2 + " (expected: 0 - " + (this.count - 1) + ')');
        } else if (count2 == 0) {
            return 0;
        } else {
            return this.file.transferTo(this.position + position2, count2, target);
        }
    }

    public void releaseExternalResources() {
        try {
            this.file.close();
        } catch (IOException e) {
            if (logger.isWarnEnabled()) {
                logger.warn("Failed to close a file.", e);
            }
        }
    }
}