package com.ning.http.client.generators;

import com.facebook.appevents.AppEventsConstants;
import com.ning.http.client.Body;
import com.ning.http.client.BodyGenerator;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InputStreamBodyGenerator implements BodyGenerator {
    /* access modifiers changed from: private */
    public static final byte[] END_PADDING = "\r\n".getBytes();
    /* access modifiers changed from: private */
    public static final byte[] ZERO = AppEventsConstants.EVENT_PARAM_VALUE_NO.getBytes();
    /* access modifiers changed from: private */
    public static final Logger logger = LoggerFactory.getLogger(InputStreamBodyGenerator.class);
    /* access modifiers changed from: private */
    public final InputStream inputStream;
    /* access modifiers changed from: private */
    public boolean patchNettyChunkingIssue = false;

    protected class ISBody implements Body {
        private byte[] chunk;
        private int endDataCount = 0;
        private boolean eof = false;

        protected ISBody() {
        }

        public long getContentLength() {
            return -1;
        }

        public long read(ByteBuffer buffer) throws IOException {
            this.chunk = new byte[(buffer.remaining() - 10)];
            int read = -1;
            try {
                read = InputStreamBodyGenerator.this.inputStream.read(this.chunk);
            } catch (IOException ex) {
                InputStreamBodyGenerator.logger.warn((String) "Unable to read", (Throwable) ex);
            }
            if (InputStreamBodyGenerator.this.patchNettyChunkingIssue) {
                if (read != -1) {
                    buffer.put(Integer.toHexString(read).getBytes());
                    buffer.put(InputStreamBodyGenerator.END_PADDING);
                    buffer.put(this.chunk, 0, read);
                    buffer.put(InputStreamBodyGenerator.END_PADDING);
                } else if (!this.eof) {
                    this.endDataCount++;
                    if (this.endDataCount == 2) {
                        this.eof = true;
                    }
                    if (this.endDataCount == 1) {
                        buffer.put(InputStreamBodyGenerator.ZERO);
                    }
                    buffer.put(InputStreamBodyGenerator.END_PADDING);
                    return (long) buffer.position();
                } else {
                    if (InputStreamBodyGenerator.this.inputStream.markSupported()) {
                        InputStreamBodyGenerator.this.inputStream.reset();
                    }
                    this.eof = false;
                    return -1;
                }
            } else if (read > 0) {
                buffer.put(this.chunk, 0, read);
            } else if (InputStreamBodyGenerator.this.inputStream.markSupported()) {
                InputStreamBodyGenerator.this.inputStream.reset();
            }
            return (long) read;
        }

        public void close() throws IOException {
            InputStreamBodyGenerator.this.inputStream.close();
        }
    }

    public InputStreamBodyGenerator(InputStream inputStream2) {
        this.inputStream = inputStream2;
        if (inputStream2.markSupported()) {
            inputStream2.mark(0);
        } else {
            logger.info("inputStream.markSupported() not supported. Some features will not work.");
        }
    }

    public Body createBody() throws IOException {
        return new ISBody();
    }

    public void patchNettyChunkingIssue(boolean patchNettyChunkingIssue2) {
        this.patchNettyChunkingIssue = patchNettyChunkingIssue2;
    }
}