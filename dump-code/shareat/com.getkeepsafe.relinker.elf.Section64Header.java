package com.getkeepsafe.relinker.elf;

import com.getkeepsafe.relinker.elf.Elf.Header;
import com.getkeepsafe.relinker.elf.Elf.SectionHeader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Section64Header extends SectionHeader {
    public Section64Header(ElfParser parser, Header header, int index) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(header.bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        this.info = parser.readWord(buffer, header.shoff + ((long) (header.shentsize * index)) + 44);
    }
}