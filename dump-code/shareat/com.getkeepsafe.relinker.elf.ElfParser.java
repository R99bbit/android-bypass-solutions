package com.getkeepsafe.relinker.elf;

import com.getkeepsafe.relinker.elf.Elf.DynamicStructure;
import com.getkeepsafe.relinker.elf.Elf.Header;
import com.getkeepsafe.relinker.elf.Elf.ProgramHeader;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ElfParser implements Closeable, Elf {
    private final int MAGIC = 1179403647;
    private final FileChannel channel;

    public ElfParser(File file) throws FileNotFoundException {
        if (file == null || !file.exists()) {
            throw new IllegalArgumentException("File is null or does not exist");
        }
        this.channel = new FileInputStream(file).getChannel();
    }

    public Header parseHeader() throws IOException {
        this.channel.position(0);
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        if (readWord(buffer, 0) != 1179403647) {
            throw new IllegalArgumentException("Invalid ELF Magic!");
        }
        short fileClass = readByte(buffer, 4);
        boolean bigEndian = readByte(buffer, 5) == 2;
        if (fileClass == 1) {
            return new Elf32Header(bigEndian, this);
        }
        if (fileClass == 2) {
            return new Elf64Header(bigEndian, this);
        }
        throw new IllegalStateException("Invalid class type!");
    }

    public List<String> parseNeededDependencies() throws IOException {
        DynamicStructure dynStructure;
        this.channel.position(0);
        List<String> dependencies = new ArrayList<>();
        Header header = parseHeader();
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(header.bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        long numProgramHeaderEntries = (long) header.phnum;
        if (numProgramHeaderEntries == 65535) {
            numProgramHeaderEntries = header.getSectionHeader(0).info;
        }
        long dynamicSectionOff = 0;
        long i = 0;
        while (true) {
            if (i >= numProgramHeaderEntries) {
                break;
            }
            ProgramHeader programHeader = header.getProgramHeader(i);
            if (programHeader.type == 2) {
                dynamicSectionOff = programHeader.offset;
                break;
            }
            i++;
        }
        if (dynamicSectionOff == 0) {
            return Collections.unmodifiableList(dependencies);
        }
        int i2 = 0;
        List<Long> neededOffsets = new ArrayList<>();
        long vStringTableOff = 0;
        do {
            dynStructure = header.getDynamicStructure(dynamicSectionOff, i2);
            if (dynStructure.tag == 1) {
                neededOffsets.add(Long.valueOf(dynStructure.val));
            } else if (dynStructure.tag == 5) {
                vStringTableOff = dynStructure.val;
            }
            i2++;
        } while (dynStructure.tag != 0);
        if (vStringTableOff == 0) {
            throw new IllegalStateException("String table offset not found!");
        }
        long stringTableOff = offsetFromVma(header, numProgramHeaderEntries, vStringTableOff);
        for (Long strOff : neededOffsets) {
            dependencies.add(readString(buffer, strOff.longValue() + stringTableOff));
        }
        return dependencies;
    }

    private long offsetFromVma(Header header, long numEntries, long vma) throws IOException {
        for (long i = 0; i < numEntries; i++) {
            ProgramHeader programHeader = header.getProgramHeader(i);
            if (programHeader.type == 1 && programHeader.vaddr <= vma && vma <= programHeader.vaddr + programHeader.memsz) {
                return (vma - programHeader.vaddr) + programHeader.offset;
            }
        }
        throw new IllegalStateException("Could not map vma to file offset!");
    }

    public void close() throws IOException {
        this.channel.close();
    }

    /* access modifiers changed from: protected */
    public String readString(ByteBuffer buffer, long offset) throws IOException {
        StringBuilder builder = new StringBuilder();
        while (true) {
            long offset2 = offset + 1;
            short c = readByte(buffer, offset);
            if (c == 0) {
                return builder.toString();
            }
            builder.append((char) c);
            offset = offset2;
        }
    }

    /* access modifiers changed from: protected */
    public long readLong(ByteBuffer buffer, long offset) throws IOException {
        read(buffer, offset, 8);
        return buffer.getLong();
    }

    /* access modifiers changed from: protected */
    public long readWord(ByteBuffer buffer, long offset) throws IOException {
        read(buffer, offset, 4);
        return ((long) buffer.getInt()) & 4294967295L;
    }

    /* access modifiers changed from: protected */
    public int readHalf(ByteBuffer buffer, long offset) throws IOException {
        read(buffer, offset, 2);
        return buffer.getShort() & 65535;
    }

    /* access modifiers changed from: protected */
    public short readByte(ByteBuffer buffer, long offset) throws IOException {
        read(buffer, offset, 1);
        return (short) (buffer.get() & 255);
    }

    /* access modifiers changed from: protected */
    public void read(ByteBuffer buffer, long offset, int length) throws IOException {
        buffer.position(0);
        buffer.limit(length);
        long bytesRead = 0;
        while (bytesRead < ((long) length)) {
            int read = this.channel.read(buffer, offset + bytesRead);
            if (read == -1) {
                throw new EOFException();
            }
            bytesRead += (long) read;
        }
        buffer.position(0);
    }
}