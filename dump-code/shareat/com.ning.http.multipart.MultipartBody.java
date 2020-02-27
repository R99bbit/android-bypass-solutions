package com.ning.http.multipart;

import com.ning.http.client.ByteArrayPart;
import com.ning.http.client.FilePart;
import com.ning.http.client.Part;
import com.ning.http.client.RandomAccessBody;
import com.ning.http.client.StringPart;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MultipartBody implements RandomAccessBody {
    private static final Logger logger = LoggerFactory.getLogger(MultipartBody.class);
    private final byte[] boundary;
    private final long contentLength;
    private FileChannel currentFileChannel;
    private FilePart currentFilePart;
    private ByteArrayInputStream currentStream;
    private int currentStreamPosition = -1;
    private boolean doneWritingParts = false;
    private boolean endWritten = false;
    private FileLocation fileLocation = FileLocation.NONE;
    private final List<RandomAccessFile> files = new ArrayList();
    private final List<Part> parts;
    private int startPart = 0;

    enum FileLocation {
        NONE,
        START,
        MIDDLE,
        END
    }

    public MultipartBody(List<Part> parts2, String contentType, long contentLength2) {
        this.boundary = MultipartEncodingUtil.getAsciiBytes(contentType.substring(contentType.indexOf("boundary=") + "boundary=".length()));
        this.parts = parts2;
        this.contentLength = contentLength2;
    }

    public void close() throws IOException {
        for (RandomAccessFile file : this.files) {
            file.close();
        }
    }

    public long getContentLength() {
        return this.contentLength;
    }

    public long read(ByteBuffer buffer) throws IOException {
        int overallLength = 0;
        try {
            int maxLength = buffer.remaining();
            if (this.startPart == this.parts.size() && this.endWritten) {
                return -1;
            }
            boolean full = false;
            while (!full && !this.doneWritingParts) {
                Part part = null;
                if (this.startPart < this.parts.size()) {
                    part = this.parts.get(this.startPart);
                }
                if (this.currentFileChannel != null) {
                    overallLength += this.currentFileChannel.read(buffer);
                    if (this.currentFileChannel.position() == this.currentFileChannel.size()) {
                        this.currentFileChannel.close();
                        this.currentFileChannel = null;
                    }
                    if (overallLength == maxLength) {
                        full = true;
                    }
                } else if (this.currentStreamPosition > -1) {
                    overallLength += writeToBuffer(buffer, maxLength - overallLength);
                    if (overallLength == maxLength) {
                        full = true;
                    }
                    if (this.startPart == this.parts.size() && this.currentStream.available() == 0) {
                        this.doneWritingParts = true;
                    }
                } else if (part instanceof StringPart) {
                    initializeStringPart((StringPart) part);
                    this.startPart++;
                } else if (part instanceof StringPart) {
                    initializeStringPart(generateClientStringpart(part));
                    this.startPart++;
                } else if (part instanceof FilePart) {
                    if (this.fileLocation == FileLocation.NONE) {
                        this.currentFilePart = (FilePart) part;
                        initializeFilePart(this.currentFilePart);
                    } else if (this.fileLocation == FileLocation.START) {
                        initializeFileBody(this.currentFilePart);
                    } else if (this.fileLocation == FileLocation.MIDDLE) {
                        initializeFileEnd(this.currentFilePart);
                    } else if (this.fileLocation == FileLocation.END) {
                        this.startPart++;
                        this.fileLocation = FileLocation.NONE;
                        if (this.startPart == this.parts.size() && this.currentStream.available() == 0) {
                            this.doneWritingParts = true;
                        }
                    }
                } else if (part instanceof FilePart) {
                    if (this.fileLocation == FileLocation.NONE) {
                        this.currentFilePart = generateClientFilePart(part);
                        initializeFilePart(this.currentFilePart);
                    } else if (this.fileLocation == FileLocation.START) {
                        initializeFileBody(this.currentFilePart);
                    } else if (this.fileLocation == FileLocation.MIDDLE) {
                        initializeFileEnd(this.currentFilePart);
                    } else if (this.fileLocation == FileLocation.END) {
                        this.startPart++;
                        this.fileLocation = FileLocation.NONE;
                        if (this.startPart == this.parts.size() && this.currentStream.available() == 0) {
                            this.doneWritingParts = true;
                        }
                    }
                } else if (part instanceof ByteArrayPart) {
                    ByteArrayPart bytePart = (ByteArrayPart) part;
                    if (this.fileLocation == FileLocation.NONE) {
                        this.currentFilePart = generateClientByteArrayPart(bytePart);
                        initializeFilePart(this.currentFilePart);
                    } else if (this.fileLocation == FileLocation.START) {
                        initializeByteArrayBody(this.currentFilePart);
                    } else if (this.fileLocation == FileLocation.MIDDLE) {
                        initializeFileEnd(this.currentFilePart);
                    } else if (this.fileLocation == FileLocation.END) {
                        this.startPart++;
                        this.fileLocation = FileLocation.NONE;
                        if (this.startPart == this.parts.size() && this.currentStream.available() == 0) {
                            this.doneWritingParts = true;
                        }
                    }
                }
            }
            if (this.doneWritingParts) {
                if (this.currentStreamPosition == -1) {
                    ByteArrayOutputStream endWriter = new ByteArrayOutputStream();
                    Part.sendMessageEnd(endWriter, this.boundary);
                    initializeBuffer(endWriter.toByteArray());
                }
                if (this.currentStreamPosition > -1) {
                    overallLength += writeToBuffer(buffer, maxLength - overallLength);
                    if (this.currentStream.available() == 0) {
                        this.currentStream.close();
                        this.currentStreamPosition = -1;
                        this.endWritten = true;
                    }
                }
            }
            return (long) overallLength;
        } catch (Exception e) {
            logger.info((String) "read exception", (Throwable) e);
            return 0;
        }
    }

    private void initializeByteArrayBody(FilePart filePart) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        filePart.sendData(output);
        initializeBuffer(output.toByteArray());
        this.fileLocation = FileLocation.MIDDLE;
    }

    private void initializeFileEnd(FilePart currentPart) throws IOException {
        initializeBuffer(generateFileEnd(currentPart).toByteArray());
        this.fileLocation = FileLocation.END;
    }

    private void initializeFileBody(FilePart currentPart) throws IOException {
        if (currentPart.getSource() instanceof FilePartSource) {
            RandomAccessFile raf = new RandomAccessFile(((FilePartSource) currentPart.getSource()).getFile(), "r");
            this.files.add(raf);
            this.currentFileChannel = raf.getChannel();
        } else {
            PartSource partSource = currentPart.getSource();
            byte[] bytes = new byte[((int) partSource.getLength())];
            partSource.createInputStream().read(bytes);
            this.currentStream = new ByteArrayInputStream(bytes);
            this.currentStreamPosition = 0;
        }
        this.fileLocation = FileLocation.MIDDLE;
    }

    private void initializeFilePart(FilePart filePart) throws IOException {
        initializeBuffer(generateFileStart(filePart).toByteArray());
        this.fileLocation = FileLocation.START;
    }

    private void initializeStringPart(StringPart currentPart) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Part.sendPart(outputStream, currentPart, this.boundary);
        initializeBuffer(outputStream.toByteArray());
    }

    private int writeToBuffer(ByteBuffer buffer, int length) throws IOException {
        int available = this.currentStream.available();
        int writeLength = Math.min(available, length);
        byte[] bytes = new byte[writeLength];
        this.currentStream.read(bytes);
        buffer.put(bytes);
        if (available <= length) {
            this.currentStream.close();
            this.currentStreamPosition = -1;
        } else {
            this.currentStreamPosition += writeLength;
        }
        return writeLength;
    }

    private void initializeBuffer(byte[] bytes) throws IOException {
        this.currentStream = new ByteArrayInputStream(bytes);
        this.currentStreamPosition = 0;
    }

    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        long handleClientPart;
        long overallLength = 0;
        if (this.startPart == this.parts.size()) {
            return this.contentLength;
        }
        int tempPart = this.startPart;
        for (Part part : this.parts) {
            if (part instanceof Part) {
                handleClientPart = handleMultiPart(target, (Part) part);
            } else {
                handleClientPart = handleClientPart(target, part);
            }
            overallLength += handleClientPart;
            tempPart++;
        }
        ByteArrayOutputStream endWriter = new ByteArrayOutputStream();
        Part.sendMessageEnd(endWriter, this.boundary);
        this.startPart = tempPart;
        return overallLength + writeToTarget(target, endWriter.toByteArray());
    }

    private long handleClientPart(WritableByteChannel target, Part part) throws IOException {
        if (part.getClass().equals(StringPart.class)) {
            return handleStringPart(target, generateClientStringpart(part));
        }
        if (part.getClass().equals(FilePart.class)) {
            return handleFilePart(target, generateClientFilePart(part));
        }
        if (!part.getClass().equals(ByteArrayPart.class)) {
            return 0;
        }
        ByteArrayPart bytePart = (ByteArrayPart) part;
        return handleByteArrayPart(target, generateClientByteArrayPart(bytePart), bytePart.getData());
    }

    private FilePart generateClientByteArrayPart(ByteArrayPart bytePart) {
        return new FilePart(bytePart.getName(), (PartSource) new ByteArrayPartSource(bytePart.getFileName(), bytePart.getData()), bytePart.getMimeType(), bytePart.getCharSet());
    }

    private FilePart generateClientFilePart(Part part) throws FileNotFoundException {
        FilePart currentPart = (FilePart) part;
        return new FilePart(currentPart.getName(), currentPart.getFile(), currentPart.getMimeType(), currentPart.getCharSet());
    }

    private StringPart generateClientStringpart(Part part) {
        StringPart stringPart = (StringPart) part;
        return new StringPart(stringPart.getName(), stringPart.getValue(), stringPart.getCharset());
    }

    private long handleByteArrayPart(WritableByteChannel target, FilePart filePart, byte[] data) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Part.sendPart(output, filePart, this.boundary);
        return writeToTarget(target, output.toByteArray());
    }

    private long handleFileEnd(WritableByteChannel target, FilePart filePart) throws IOException {
        return writeToTarget(target, generateFileEnd(filePart).toByteArray());
    }

    private ByteArrayOutputStream generateFileEnd(FilePart filePart) throws IOException {
        ByteArrayOutputStream endOverhead = new ByteArrayOutputStream();
        filePart.sendEnd(endOverhead);
        return endOverhead;
    }

    private long handleFileHeaders(WritableByteChannel target, FilePart filePart) throws IOException {
        return writeToTarget(target, generateFileStart(filePart).toByteArray());
    }

    private ByteArrayOutputStream generateFileStart(FilePart filePart) throws IOException {
        ByteArrayOutputStream overhead = new ByteArrayOutputStream();
        filePart.sendStart(overhead, this.boundary);
        filePart.sendDispositionHeader(overhead);
        filePart.sendContentTypeHeader(overhead);
        filePart.sendTransferEncodingHeader(overhead);
        filePart.sendContentIdHeader(overhead);
        filePart.sendEndOfHeader(overhead);
        return overhead;
    }

    private long handleFilePart(WritableByteChannel target, FilePart filePart) throws IOException {
        FilePartStallHandler handler = new FilePartStallHandler(filePart.getStalledTime(), filePart);
        handler.start();
        if (!(filePart.getSource() instanceof FilePartSource)) {
            return handlePartSource(target, filePart);
        }
        int length = (int) (((long) 0) + handleFileHeaders(target, filePart));
        File file = ((FilePartSource) filePart.getSource()).getFile();
        RandomAccessFile raf = new RandomAccessFile(file, "r");
        this.files.add(raf);
        FileChannel fc = raf.getChannel();
        long l = file.length();
        int fileLength = 0;
        synchronized (fc) {
            while (((long) fileLength) != l) {
                if (handler.isFailed()) {
                    logger.debug("Stalled error");
                    throw new FileUploadStalledException();
                }
                try {
                    long nWrite = fc.transferTo((long) fileLength, l, target);
                    if (nWrite == 0) {
                        logger.info("Waiting for writing...");
                        try {
                            fc.wait(50);
                        } catch (InterruptedException e) {
                            logger.trace(e.getMessage(), (Throwable) e);
                        }
                    } else {
                        handler.writeHappened();
                    }
                    fileLength = (int) (((long) fileLength) + nWrite);
                } catch (IOException ex) {
                    String message = ex.getMessage();
                    if (message == null || !message.equalsIgnoreCase("Resource temporarily unavailable")) {
                        throw ex;
                    }
                    try {
                        fc.wait(1000);
                    } catch (InterruptedException e2) {
                        logger.trace(e2.getMessage(), (Throwable) e2);
                    }
                    logger.warn("Experiencing NIO issue http://bugs.sun.com/view_bug.do?bug_id=5103988. Retrying");
                }
            }
        }
        handler.completed();
        fc.close();
        return (long) ((int) (((long) length) + handleFileEnd(target, filePart)));
    }

    private long handlePartSource(WritableByteChannel target, FilePart filePart) throws IOException {
        int length = (int) (((long) 0) + handleFileHeaders(target, filePart));
        InputStream stream = filePart.getSource().createInputStream();
        int nRead = 0;
        while (nRead != -1) {
            try {
                byte[] bytes = new byte[8192];
                nRead = stream.read(bytes);
                if (nRead > 0) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream(nRead);
                    bos.write(bytes, 0, nRead);
                    length = (int) (((long) length) + writeToTarget(target, bos.toByteArray()));
                }
            } catch (Throwable th) {
                stream.close();
                throw th;
            }
        }
        stream.close();
        return (long) ((int) (((long) length) + handleFileEnd(target, filePart)));
    }

    private long handleStringPart(WritableByteChannel target, StringPart currentPart) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Part.sendPart(outputStream, currentPart, this.boundary);
        return writeToTarget(target, outputStream.toByteArray());
    }

    private long handleMultiPart(WritableByteChannel target, Part currentPart) throws IOException {
        if (currentPart.getClass().equals(StringPart.class)) {
            return handleStringPart(target, (StringPart) currentPart);
        }
        if (currentPart.getClass().equals(FilePart.class)) {
            return handleFilePart(target, (FilePart) currentPart);
        }
        return 0;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:32:0x0076, code lost:
        return (long) r13;
     */
    /* JADX WARNING: Removed duplicated region for block: B:57:0x00d5  */
    /* JADX WARNING: Removed duplicated region for block: B:67:0x00b9 A[SYNTHETIC] */
    private long writeToTarget(WritableByteChannel target, byte[] bytes) throws IOException {
        int maxSpin;
        Selector selector;
        int written = 0;
        int maxSpin2 = 0;
        synchronized (bytes) {
            try {
                ByteBuffer message = ByteBuffer.wrap(bytes);
                if (target instanceof SocketChannel) {
                    selector = Selector.open();
                    ((SocketChannel) target).register(selector, 4);
                    while (written < bytes.length) {
                        selector.select(1000);
                        maxSpin2++;
                        for (SelectionKey key : selector.selectedKeys()) {
                            if (key.isWritable()) {
                                written += target.write(message);
                                maxSpin2 = 0;
                            }
                        }
                        if (maxSpin2 >= 10) {
                            throw new IOException("Unable to write on channel " + target);
                        }
                    }
                    selector.close();
                } else {
                    while (true) {
                        try {
                            maxSpin = maxSpin2;
                            if (!target.isOpen() || written >= bytes.length) {
                            } else {
                                long nWrite = (long) target.write(message);
                                written = (int) (((long) written) + nWrite);
                                if (nWrite == 0) {
                                    maxSpin2 = maxSpin + 1;
                                    if (maxSpin < 10) {
                                        logger.info("Waiting for writing...");
                                        try {
                                            bytes.wait(1000);
                                        } catch (InterruptedException e) {
                                            logger.trace(e.getMessage(), (Throwable) e);
                                        }
                                    }
                                    if (maxSpin2 < 10) {
                                        throw new IOException("Unable to write on channel " + target);
                                    }
                                    maxSpin2 = 0;
                                } else {
                                    maxSpin2 = maxSpin;
                                    if (maxSpin2 < 10) {
                                    }
                                }
                            }
                        } catch (Throwable th) {
                            th = th;
                            int i = maxSpin;
                            throw th;
                        }
                    }
                }
            } catch (Throwable th2) {
                th = th2;
                throw th;
            }
        }
    }
}