package com.getkeepsafe.relinker.elf;

import com.getkeepsafe.relinker.elf.Elf.Header;
import com.getkeepsafe.relinker.elf.Elf.ProgramHeader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Program64Header extends ProgramHeader {
    public Program64Header(ElfParser parser, Header header, long index) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(header.bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        long baseOffset = header.phoff + (((long) header.phentsize) * index);
        this.type = parser.readWord(buffer, baseOffset);
        this.offset = parser.readLong(buffer, 8 + baseOffset);
        this.vaddr = parser.readLong(buffer, 16 + baseOffset);
        this.memsz = parser.readLong(buffer, 40 + baseOffset);
    }
}