package org.jboss.netty.handler.codec.serialization;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;

class CompactObjectOutputStream extends ObjectOutputStream {
    static final int TYPE_FAT_DESCRIPTOR = 0;
    static final int TYPE_THIN_DESCRIPTOR = 1;

    CompactObjectOutputStream(OutputStream out) throws IOException {
        super(out);
    }

    /* access modifiers changed from: protected */
    public void writeStreamHeader() throws IOException {
        writeByte(5);
    }

    /* access modifiers changed from: protected */
    public void writeClassDescriptor(ObjectStreamClass desc) throws IOException {
        Class<?> forClass = desc.forClass();
        if (forClass.isPrimitive() || forClass.isArray() || forClass.isInterface() || desc.getSerialVersionUID() == 0) {
            write(0);
            super.writeClassDescriptor(desc);
            return;
        }
        write(1);
        writeUTF(desc.getName());
    }
}