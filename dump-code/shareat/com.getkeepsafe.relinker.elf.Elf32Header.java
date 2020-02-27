package com.getkeepsafe.relinker.elf;

import com.getkeepsafe.relinker.elf.Elf.DynamicStructure;
import com.getkeepsafe.relinker.elf.Elf.Header;
import com.getkeepsafe.relinker.elf.Elf.ProgramHeader;
import com.getkeepsafe.relinker.elf.Elf.SectionHeader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Elf32Header extends Header {
    private final ElfParser parser;

    public Elf32Header(boolean bigEndian, ElfParser parser2) throws IOException {
        this.bigEndian = bigEndian;
        this.parser = parser2;
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        this.type = parser2.readHalf(buffer, 16);
        this.phoff = parser2.readWord(buffer, 28);
        this.shoff = parser2.readWord(buffer, 32);
        this.phentsize = parser2.readHalf(buffer, 42);
        this.phnum = parser2.readHalf(buffer, 44);
        this.shentsize = parser2.readHalf(buffer, 46);
        this.shnum = parser2.readHalf(buffer, 48);
        this.shstrndx = parser2.readHalf(buffer, 50);
    }

    public SectionHeader getSectionHeader(int index) throws IOException {
        return new Section32Header(this.parser, this, index);
    }

    public ProgramHeader getProgramHeader(long index) throws IOException {
        return new Program32Header(this.parser, this, index);
    }

    public DynamicStructure getDynamicStructure(long baseOffset, int index) throws IOException {
        return new Dynamic32Structure(this.parser, this, baseOffset, index);
    }
}