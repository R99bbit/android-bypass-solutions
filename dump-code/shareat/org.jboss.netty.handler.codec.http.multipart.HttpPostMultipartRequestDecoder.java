package org.jboss.netty.handler.codec.http.multipart;

import com.facebook.share.internal.ShareConstants;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpConstants;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.multipart.HttpPostBodyUtil.TransferEncodingMechanism;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.EndOfDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.ErrorDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.IncompatibleDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.NotEnoughDataDecoderException;
import org.jboss.netty.util.internal.CaseIgnoringComparator;
import org.jboss.netty.util.internal.StringUtil;

public class HttpPostMultipartRequestDecoder implements InterfaceHttpPostRequestDecoder {
    private final List<InterfaceHttpData> bodyListHttpData;
    private int bodyListHttpDataRank;
    private final Map<String, List<InterfaceHttpData>> bodyMapHttpData;
    private Charset charset;
    private Attribute currentAttribute;
    private Map<String, Attribute> currentFieldAttributes;
    private FileUpload currentFileUpload;
    private MultiPartStatus currentStatus;
    private final HttpDataFactory factory;
    private boolean isLastChunk;
    private String multipartDataBoundary;
    private String multipartMixedBoundary;
    private final HttpRequest request;
    private ChannelBuffer undecodedChunk;

    public HttpPostMultipartRequestDecoder(HttpRequest request2) throws ErrorDataDecoderException, IncompatibleDataDecoderException {
        this(new DefaultHttpDataFactory(16384), request2, HttpConstants.DEFAULT_CHARSET);
    }

    public HttpPostMultipartRequestDecoder(HttpDataFactory factory2, HttpRequest request2) throws ErrorDataDecoderException, IncompatibleDataDecoderException {
        this(factory2, request2, HttpConstants.DEFAULT_CHARSET);
    }

    public HttpPostMultipartRequestDecoder(HttpDataFactory factory2, HttpRequest request2, Charset charset2) throws ErrorDataDecoderException, IncompatibleDataDecoderException {
        this.bodyListHttpData = new ArrayList();
        this.bodyMapHttpData = new TreeMap(CaseIgnoringComparator.INSTANCE);
        this.currentStatus = MultiPartStatus.NOTSTARTED;
        if (factory2 == null) {
            throw new NullPointerException("factory");
        } else if (request2 == null) {
            throw new NullPointerException(ShareConstants.WEB_DIALOG_RESULT_PARAM_REQUEST_ID);
        } else if (charset2 == null) {
            throw new NullPointerException("charset");
        } else {
            this.request = request2;
            this.charset = charset2;
            this.factory = factory2;
            setMultipart(this.request.headers().get("Content-Type"));
            if (!this.request.isChunked()) {
                this.undecodedChunk = this.request.getContent();
                this.isLastChunk = true;
                parseBody();
            }
        }
    }

    private void setMultipart(String contentType) throws ErrorDataDecoderException {
        String[] dataBoundary = HttpPostRequestDecoder.getMultipartDataBoundary(contentType);
        if (dataBoundary != null) {
            this.multipartDataBoundary = dataBoundary[0];
            if (dataBoundary.length > 1 && dataBoundary[1] != null) {
                this.charset = Charset.forName(dataBoundary[1]);
            }
        } else {
            this.multipartDataBoundary = null;
        }
        this.currentStatus = MultiPartStatus.HEADERDELIMITER;
    }

    public boolean isMultipart() {
        return true;
    }

    public List<InterfaceHttpData> getBodyHttpDatas() throws NotEnoughDataDecoderException {
        if (this.isLastChunk) {
            return this.bodyListHttpData;
        }
        throw new NotEnoughDataDecoderException();
    }

    public List<InterfaceHttpData> getBodyHttpDatas(String name) throws NotEnoughDataDecoderException {
        if (this.isLastChunk) {
            return this.bodyMapHttpData.get(name);
        }
        throw new NotEnoughDataDecoderException();
    }

    public InterfaceHttpData getBodyHttpData(String name) throws NotEnoughDataDecoderException {
        if (!this.isLastChunk) {
            throw new NotEnoughDataDecoderException();
        }
        List<InterfaceHttpData> list = this.bodyMapHttpData.get(name);
        if (list != null) {
            return list.get(0);
        }
        return null;
    }

    public void offer(HttpChunk chunk) throws ErrorDataDecoderException {
        ChannelBuffer chunked = chunk.getContent();
        if (this.undecodedChunk == null) {
            this.undecodedChunk = chunked;
        } else {
            this.undecodedChunk = ChannelBuffers.wrappedBuffer(this.undecodedChunk, chunked);
        }
        if (chunk.isLast()) {
            this.isLastChunk = true;
        }
        parseBody();
    }

    public boolean hasNext() throws EndOfDataDecoderException {
        if (this.currentStatus != MultiPartStatus.EPILOGUE || this.bodyListHttpDataRank < this.bodyListHttpData.size()) {
            return !this.bodyListHttpData.isEmpty() && this.bodyListHttpDataRank < this.bodyListHttpData.size();
        }
        throw new EndOfDataDecoderException();
    }

    public InterfaceHttpData next() throws EndOfDataDecoderException {
        if (!hasNext()) {
            return null;
        }
        List<InterfaceHttpData> list = this.bodyListHttpData;
        int i = this.bodyListHttpDataRank;
        this.bodyListHttpDataRank = i + 1;
        return list.get(i);
    }

    private void parseBody() throws ErrorDataDecoderException {
        if (this.currentStatus != MultiPartStatus.PREEPILOGUE && this.currentStatus != MultiPartStatus.EPILOGUE) {
            parseBodyMultipart();
        } else if (this.isLastChunk) {
            this.currentStatus = MultiPartStatus.EPILOGUE;
        }
    }

    private void addHttpData(InterfaceHttpData data) {
        if (data != null) {
            List<InterfaceHttpData> datas = this.bodyMapHttpData.get(data.getName());
            if (datas == null) {
                datas = new ArrayList<>(1);
                this.bodyMapHttpData.put(data.getName(), datas);
            }
            datas.add(data);
            this.bodyListHttpData.add(data);
        }
    }

    private void parseBodyMultipart() throws ErrorDataDecoderException {
        if (this.undecodedChunk != null && this.undecodedChunk.readableBytes() != 0) {
            InterfaceHttpData data = decodeMultipart(this.currentStatus);
            while (data != null) {
                addHttpData(data);
                if (this.currentStatus != MultiPartStatus.PREEPILOGUE && this.currentStatus != MultiPartStatus.EPILOGUE) {
                    data = decodeMultipart(this.currentStatus);
                } else {
                    return;
                }
            }
        }
    }

    private InterfaceHttpData decodeMultipart(MultiPartStatus state) throws ErrorDataDecoderException {
        switch (state) {
            case NOTSTARTED:
                throw new ErrorDataDecoderException((String) "Should not be called with the current status");
            case PREAMBLE:
                throw new ErrorDataDecoderException((String) "Should not be called with the current status");
            case HEADERDELIMITER:
                return findMultipartDelimiter(this.multipartDataBoundary, MultiPartStatus.DISPOSITION, MultiPartStatus.PREEPILOGUE);
            case DISPOSITION:
                return findMultipartDisposition();
            case FIELD:
                Charset localCharset = null;
                Attribute charsetAttribute = this.currentFieldAttributes.get("charset");
                if (charsetAttribute != null) {
                    try {
                        localCharset = Charset.forName(charsetAttribute.getValue());
                    } catch (IOException e) {
                        throw new ErrorDataDecoderException((Throwable) e);
                    }
                }
                Attribute nameAttribute = this.currentFieldAttributes.get("name");
                if (this.currentAttribute == null) {
                    try {
                        this.currentAttribute = this.factory.createAttribute(this.request, cleanString(nameAttribute.getValue()));
                        if (localCharset != null) {
                            this.currentAttribute.setCharset(localCharset);
                        }
                    } catch (NullPointerException e2) {
                        throw new ErrorDataDecoderException((Throwable) e2);
                    } catch (IllegalArgumentException e3) {
                        throw new ErrorDataDecoderException((Throwable) e3);
                    } catch (IOException e4) {
                        throw new ErrorDataDecoderException((Throwable) e4);
                    }
                }
                try {
                    loadFieldMultipart(this.multipartDataBoundary);
                    Attribute attribute = this.currentAttribute;
                    this.currentAttribute = null;
                    this.currentFieldAttributes = null;
                    this.currentStatus = MultiPartStatus.HEADERDELIMITER;
                    return attribute;
                } catch (NotEnoughDataDecoderException e5) {
                    return null;
                }
            case FILEUPLOAD:
                return getFileUpload(this.multipartDataBoundary);
            case MIXEDDELIMITER:
                return findMultipartDelimiter(this.multipartMixedBoundary, MultiPartStatus.MIXEDDISPOSITION, MultiPartStatus.HEADERDELIMITER);
            case MIXEDDISPOSITION:
                return findMultipartDisposition();
            case MIXEDFILEUPLOAD:
                return getFileUpload(this.multipartMixedBoundary);
            case PREEPILOGUE:
                return null;
            case EPILOGUE:
                return null;
            default:
                throw new ErrorDataDecoderException((String) "Shouldn't reach here.");
        }
    }

    /* access modifiers changed from: 0000 */
    public void skipControlCharacters() throws NotEnoughDataDecoderException {
        try {
            SeekAheadOptimize sao = new SeekAheadOptimize(this.undecodedChunk);
            while (sao.pos < sao.limit) {
                byte[] bArr = sao.bytes;
                int i = sao.pos;
                sao.pos = i + 1;
                char c = (char) (bArr[i] & 255);
                if (!Character.isISOControl(c) && !Character.isWhitespace(c)) {
                    sao.setReadPosition(1);
                    return;
                }
            }
            throw new NotEnoughDataDecoderException((String) "Access out of bounds");
        } catch (SeekAheadNoBackArrayException e) {
            try {
                skipControlCharactersStandard();
            } catch (IndexOutOfBoundsException e1) {
                throw new NotEnoughDataDecoderException((Throwable) e1);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void skipControlCharactersStandard() {
        while (true) {
            char c = (char) this.undecodedChunk.readUnsignedByte();
            if (!Character.isISOControl(c) && !Character.isWhitespace(c)) {
                this.undecodedChunk.readerIndex(this.undecodedChunk.readerIndex() - 1);
                return;
            }
        }
    }

    private InterfaceHttpData findMultipartDelimiter(String delimiter, MultiPartStatus dispositionStatus, MultiPartStatus closeDelimiterStatus) throws ErrorDataDecoderException {
        int readerIndex = this.undecodedChunk.readerIndex();
        try {
            skipControlCharacters();
            skipOneLine();
            try {
                String newline = readDelimiter(delimiter);
                if (newline.equals(delimiter)) {
                    this.currentStatus = dispositionStatus;
                    return decodeMultipart(dispositionStatus);
                } else if (newline.equals(delimiter + "--")) {
                    this.currentStatus = closeDelimiterStatus;
                    if (this.currentStatus != MultiPartStatus.HEADERDELIMITER) {
                        return null;
                    }
                    this.currentFieldAttributes = null;
                    return decodeMultipart(MultiPartStatus.HEADERDELIMITER);
                } else {
                    this.undecodedChunk.readerIndex(readerIndex);
                    throw new ErrorDataDecoderException((String) "No Multipart delimiter found");
                }
            } catch (NotEnoughDataDecoderException e) {
                this.undecodedChunk.readerIndex(readerIndex);
                return null;
            }
        } catch (NotEnoughDataDecoderException e2) {
            this.undecodedChunk.readerIndex(readerIndex);
            return null;
        }
    }

    private InterfaceHttpData findMultipartDisposition() throws ErrorDataDecoderException {
        String value;
        int readerIndex = this.undecodedChunk.readerIndex();
        if (this.currentStatus == MultiPartStatus.DISPOSITION) {
            this.currentFieldAttributes = new TreeMap(CaseIgnoringComparator.INSTANCE);
        }
        while (!skipOneLine()) {
            try {
                skipControlCharacters();
                String newline = readLine();
                String[] contents = splitMultipartHeader(newline);
                if (contents[0].equalsIgnoreCase("Content-Disposition")) {
                    boolean checkSecondArg = this.currentStatus == MultiPartStatus.DISPOSITION ? contents[1].equalsIgnoreCase(HttpPostBodyUtil.FORM_DATA) : contents[1].equalsIgnoreCase(HttpPostBodyUtil.ATTACHMENT) || contents[1].equalsIgnoreCase("file");
                    if (checkSecondArg) {
                        int i = 2;
                        while (i < contents.length) {
                            String[] values = StringUtil.split(contents[i], '=');
                            try {
                                String name = cleanString(values[0]);
                                String value2 = values[1];
                                if (HttpPostBodyUtil.FILENAME.equals(name)) {
                                    value = value2.substring(1, value2.length() - 1);
                                } else {
                                    value = cleanString(value2);
                                }
                                Attribute attribute = this.factory.createAttribute(this.request, name, value);
                                this.currentFieldAttributes.put(attribute.getName(), attribute);
                                i++;
                            } catch (NullPointerException e) {
                                throw new ErrorDataDecoderException((Throwable) e);
                            } catch (IllegalArgumentException e2) {
                                throw new ErrorDataDecoderException((Throwable) e2);
                            }
                        }
                    }
                } else if (contents[0].equalsIgnoreCase(Names.CONTENT_TRANSFER_ENCODING)) {
                    try {
                        this.currentFieldAttributes.put(Names.CONTENT_TRANSFER_ENCODING, this.factory.createAttribute(this.request, Names.CONTENT_TRANSFER_ENCODING, cleanString(contents[1])));
                    } catch (NullPointerException e3) {
                        throw new ErrorDataDecoderException((Throwable) e3);
                    } catch (IllegalArgumentException e4) {
                        throw new ErrorDataDecoderException((Throwable) e4);
                    }
                } else if (contents[0].equalsIgnoreCase("Content-Length")) {
                    try {
                        this.currentFieldAttributes.put("Content-Length", this.factory.createAttribute(this.request, "Content-Length", cleanString(contents[1])));
                    } catch (NullPointerException e5) {
                        throw new ErrorDataDecoderException((Throwable) e5);
                    } catch (IllegalArgumentException e6) {
                        throw new ErrorDataDecoderException((Throwable) e6);
                    }
                } else if (!contents[0].equalsIgnoreCase("Content-Type")) {
                    throw new ErrorDataDecoderException("Unknown Params: " + newline);
                } else if (!contents[1].equalsIgnoreCase(HttpPostBodyUtil.MULTIPART_MIXED)) {
                    for (int i2 = 1; i2 < contents.length; i2++) {
                        if (contents[i2].toLowerCase().startsWith("charset")) {
                            try {
                                this.currentFieldAttributes.put("charset", this.factory.createAttribute(this.request, "charset", cleanString(StringUtil.split(contents[i2], '=')[1])));
                            } catch (NullPointerException e7) {
                                throw new ErrorDataDecoderException((Throwable) e7);
                            } catch (IllegalArgumentException e8) {
                                throw new ErrorDataDecoderException((Throwable) e8);
                            }
                        } else {
                            try {
                                Attribute attribute2 = this.factory.createAttribute(this.request, cleanString(contents[0]), contents[i2]);
                                this.currentFieldAttributes.put(attribute2.getName(), attribute2);
                            } catch (NullPointerException e9) {
                                throw new ErrorDataDecoderException((Throwable) e9);
                            } catch (IllegalArgumentException e10) {
                                throw new ErrorDataDecoderException((Throwable) e10);
                            }
                        }
                    }
                } else if (this.currentStatus == MultiPartStatus.DISPOSITION) {
                    this.multipartMixedBoundary = "--" + StringUtil.split(contents[2], '=')[1];
                    this.currentStatus = MultiPartStatus.MIXEDDELIMITER;
                    return decodeMultipart(MultiPartStatus.MIXEDDELIMITER);
                } else {
                    throw new ErrorDataDecoderException((String) "Mixed Multipart found in a previous Mixed Multipart");
                }
            } catch (NotEnoughDataDecoderException e11) {
                this.undecodedChunk.readerIndex(readerIndex);
                return null;
            }
        }
        Attribute filenameAttribute = this.currentFieldAttributes.get(HttpPostBodyUtil.FILENAME);
        if (this.currentStatus == MultiPartStatus.DISPOSITION) {
            if (filenameAttribute != null) {
                this.currentStatus = MultiPartStatus.FILEUPLOAD;
                return decodeMultipart(MultiPartStatus.FILEUPLOAD);
            }
            this.currentStatus = MultiPartStatus.FIELD;
            return decodeMultipart(MultiPartStatus.FIELD);
        } else if (filenameAttribute != null) {
            this.currentStatus = MultiPartStatus.MIXEDFILEUPLOAD;
            return decodeMultipart(MultiPartStatus.MIXEDFILEUPLOAD);
        } else {
            throw new ErrorDataDecoderException((String) "Filename not found");
        }
    }

    private InterfaceHttpData getFileUpload(String delimiter) throws ErrorDataDecoderException {
        long size;
        Attribute encoding = this.currentFieldAttributes.get(Names.CONTENT_TRANSFER_ENCODING);
        Charset localCharset = this.charset;
        TransferEncodingMechanism mechanism = TransferEncodingMechanism.BIT7;
        if (encoding != null) {
            try {
                String code = encoding.getValue().toLowerCase();
                if (code.equals(TransferEncodingMechanism.BIT7.value())) {
                    localCharset = HttpPostBodyUtil.US_ASCII;
                } else if (code.equals(TransferEncodingMechanism.BIT8.value())) {
                    localCharset = HttpPostBodyUtil.ISO_8859_1;
                    mechanism = TransferEncodingMechanism.BIT8;
                } else if (code.equals(TransferEncodingMechanism.BINARY.value())) {
                    mechanism = TransferEncodingMechanism.BINARY;
                } else {
                    throw new ErrorDataDecoderException("TransferEncoding Unknown: " + code);
                }
            } catch (IOException e) {
                throw new ErrorDataDecoderException((Throwable) e);
            }
        }
        Attribute charsetAttribute = this.currentFieldAttributes.get("charset");
        if (charsetAttribute != null) {
            try {
                localCharset = Charset.forName(charsetAttribute.getValue());
            } catch (IOException e2) {
                throw new ErrorDataDecoderException((Throwable) e2);
            }
        }
        if (this.currentFileUpload == null) {
            Attribute filenameAttribute = this.currentFieldAttributes.get(HttpPostBodyUtil.FILENAME);
            Attribute nameAttribute = this.currentFieldAttributes.get("name");
            Attribute contentTypeAttribute = this.currentFieldAttributes.get("Content-Type");
            if (contentTypeAttribute == null) {
                contentTypeAttribute = new MemoryAttribute("Content-Type");
                try {
                    contentTypeAttribute.setValue("application/octet-stream");
                } catch (IOException e3) {
                    throw new ErrorDataDecoderException((String) "Content-Type is absent but required, and cannot be reverted to default");
                }
            }
            Attribute lengthAttribute = this.currentFieldAttributes.get("Content-Length");
            if (lengthAttribute != null) {
                try {
                    size = Long.parseLong(lengthAttribute.getValue());
                } catch (IOException e4) {
                    throw new ErrorDataDecoderException((Throwable) e4);
                } catch (NumberFormatException e5) {
                    size = 0;
                }
            } else {
                size = 0;
            }
            try {
                this.currentFileUpload = this.factory.createFileUpload(this.request, cleanString(nameAttribute.getValue()), cleanString(filenameAttribute.getValue()), contentTypeAttribute.getValue(), mechanism.value(), localCharset, size);
            } catch (NullPointerException e6) {
                throw new ErrorDataDecoderException((Throwable) e6);
            } catch (IllegalArgumentException e7) {
                throw new ErrorDataDecoderException((Throwable) e7);
            } catch (IOException e8) {
                throw new ErrorDataDecoderException((Throwable) e8);
            }
        }
        try {
            readFileUploadByteMultipart(delimiter);
            if (!this.currentFileUpload.isCompleted()) {
                return null;
            }
            if (this.currentStatus == MultiPartStatus.FILEUPLOAD) {
                this.currentStatus = MultiPartStatus.HEADERDELIMITER;
                this.currentFieldAttributes = null;
            } else {
                this.currentStatus = MultiPartStatus.MIXEDDELIMITER;
                cleanMixedAttributes();
            }
            FileUpload fileUpload = this.currentFileUpload;
            this.currentFileUpload = null;
            return fileUpload;
        } catch (NotEnoughDataDecoderException e9) {
            return null;
        }
    }

    public void cleanFiles() {
        this.factory.cleanRequestHttpDatas(this.request);
    }

    public void removeHttpDataFromClean(InterfaceHttpData data) {
        this.factory.removeHttpDataFromClean(this.request, data);
    }

    private void cleanMixedAttributes() {
        this.currentFieldAttributes.remove("charset");
        this.currentFieldAttributes.remove("Content-Length");
        this.currentFieldAttributes.remove(Names.CONTENT_TRANSFER_ENCODING);
        this.currentFieldAttributes.remove("Content-Type");
        this.currentFieldAttributes.remove(HttpPostBodyUtil.FILENAME);
    }

    private String readLineStandard() throws NotEnoughDataDecoderException {
        int readerIndex = this.undecodedChunk.readerIndex();
        try {
            ChannelBuffer line = ChannelBuffers.dynamicBuffer(64);
            while (this.undecodedChunk.readable()) {
                byte nextByte = this.undecodedChunk.readByte();
                if (nextByte == 13) {
                    if (this.undecodedChunk.readByte() == 10) {
                        return line.toString(this.charset);
                    }
                } else if (nextByte == 10) {
                    return line.toString(this.charset);
                } else {
                    line.writeByte(nextByte);
                }
            }
            this.undecodedChunk.readerIndex(readerIndex);
            throw new NotEnoughDataDecoderException();
        } catch (IndexOutOfBoundsException e) {
            this.undecodedChunk.readerIndex(readerIndex);
            throw new NotEnoughDataDecoderException((Throwable) e);
        }
    }

    private String readLine() throws NotEnoughDataDecoderException {
        try {
            SeekAheadOptimize sao = new SeekAheadOptimize(this.undecodedChunk);
            int readerIndex = this.undecodedChunk.readerIndex();
            try {
                ChannelBuffer line = ChannelBuffers.dynamicBuffer(64);
                while (sao.pos < sao.limit) {
                    byte[] bArr = sao.bytes;
                    int i = sao.pos;
                    sao.pos = i + 1;
                    byte nextByte = bArr[i];
                    if (nextByte == 13) {
                        if (sao.pos < sao.limit) {
                            byte[] bArr2 = sao.bytes;
                            int i2 = sao.pos;
                            sao.pos = i2 + 1;
                            if (bArr2[i2] == 10) {
                                sao.setReadPosition(0);
                                return line.toString(this.charset);
                            }
                        } else {
                            line.writeByte(nextByte);
                        }
                    } else if (nextByte == 10) {
                        sao.setReadPosition(0);
                        return line.toString(this.charset);
                    } else {
                        line.writeByte(nextByte);
                    }
                }
                this.undecodedChunk.readerIndex(readerIndex);
                throw new NotEnoughDataDecoderException();
            } catch (IndexOutOfBoundsException e) {
                this.undecodedChunk.readerIndex(readerIndex);
                throw new NotEnoughDataDecoderException((Throwable) e);
            }
        } catch (SeekAheadNoBackArrayException e2) {
            return readLineStandard();
        }
    }

    private String readDelimiterStandard(String delimiter) throws NotEnoughDataDecoderException {
        int readerIndex = this.undecodedChunk.readerIndex();
        try {
            StringBuilder sb = new StringBuilder(64);
            int delimiterPos = 0;
            int len = delimiter.length();
            while (this.undecodedChunk.readable() && delimiterPos < len) {
                byte nextByte = this.undecodedChunk.readByte();
                if (nextByte == delimiter.charAt(delimiterPos)) {
                    delimiterPos++;
                    sb.append((char) nextByte);
                } else {
                    this.undecodedChunk.readerIndex(readerIndex);
                    throw new NotEnoughDataDecoderException();
                }
            }
            if (this.undecodedChunk.readable()) {
                byte nextByte2 = this.undecodedChunk.readByte();
                if (nextByte2 == 13) {
                    if (this.undecodedChunk.readByte() == 10) {
                        return sb.toString();
                    }
                    this.undecodedChunk.readerIndex(readerIndex);
                    throw new NotEnoughDataDecoderException();
                } else if (nextByte2 == 10) {
                    return sb.toString();
                } else {
                    if (nextByte2 == 45) {
                        sb.append('-');
                        if (this.undecodedChunk.readByte() == 45) {
                            sb.append('-');
                            if (!this.undecodedChunk.readable()) {
                                return sb.toString();
                            }
                            byte nextByte3 = this.undecodedChunk.readByte();
                            if (nextByte3 == 13) {
                                if (this.undecodedChunk.readByte() == 10) {
                                    return sb.toString();
                                }
                                this.undecodedChunk.readerIndex(readerIndex);
                                throw new NotEnoughDataDecoderException();
                            } else if (nextByte3 == 10) {
                                return sb.toString();
                            } else {
                                this.undecodedChunk.readerIndex(this.undecodedChunk.readerIndex() - 1);
                                return sb.toString();
                            }
                        }
                    }
                }
            }
            this.undecodedChunk.readerIndex(readerIndex);
            throw new NotEnoughDataDecoderException();
        } catch (IndexOutOfBoundsException e) {
            this.undecodedChunk.readerIndex(readerIndex);
            throw new NotEnoughDataDecoderException((Throwable) e);
        }
    }

    private String readDelimiter(String delimiter) throws NotEnoughDataDecoderException {
        try {
            SeekAheadOptimize sao = new SeekAheadOptimize(this.undecodedChunk);
            int readerIndex = this.undecodedChunk.readerIndex();
            int delimiterPos = 0;
            int len = delimiter.length();
            try {
                StringBuilder sb = new StringBuilder(64);
                while (sao.pos < sao.limit && delimiterPos < len) {
                    byte[] bArr = sao.bytes;
                    int i = sao.pos;
                    sao.pos = i + 1;
                    byte nextByte = bArr[i];
                    if (nextByte == delimiter.charAt(delimiterPos)) {
                        delimiterPos++;
                        sb.append((char) nextByte);
                    } else {
                        this.undecodedChunk.readerIndex(readerIndex);
                        throw new NotEnoughDataDecoderException();
                    }
                }
                if (sao.pos < sao.limit) {
                    byte[] bArr2 = sao.bytes;
                    int i2 = sao.pos;
                    sao.pos = i2 + 1;
                    byte nextByte2 = bArr2[i2];
                    if (nextByte2 == 13) {
                        if (sao.pos < sao.limit) {
                            byte[] bArr3 = sao.bytes;
                            int i3 = sao.pos;
                            sao.pos = i3 + 1;
                            if (bArr3[i3] == 10) {
                                sao.setReadPosition(0);
                                return sb.toString();
                            }
                        } else {
                            this.undecodedChunk.readerIndex(readerIndex);
                            throw new NotEnoughDataDecoderException();
                        }
                    } else if (nextByte2 == 10) {
                        sao.setReadPosition(0);
                        return sb.toString();
                    } else if (nextByte2 == 45) {
                        sb.append('-');
                        if (sao.pos < sao.limit) {
                            byte[] bArr4 = sao.bytes;
                            int i4 = sao.pos;
                            sao.pos = i4 + 1;
                            if (bArr4[i4] == 45) {
                                sb.append('-');
                                if (sao.pos < sao.limit) {
                                    byte[] bArr5 = sao.bytes;
                                    int i5 = sao.pos;
                                    sao.pos = i5 + 1;
                                    byte nextByte3 = bArr5[i5];
                                    if (nextByte3 == 13) {
                                        if (sao.pos < sao.limit) {
                                            byte[] bArr6 = sao.bytes;
                                            int i6 = sao.pos;
                                            sao.pos = i6 + 1;
                                            if (bArr6[i6] == 10) {
                                                sao.setReadPosition(0);
                                                return sb.toString();
                                            }
                                        } else {
                                            this.undecodedChunk.readerIndex(readerIndex);
                                            throw new NotEnoughDataDecoderException();
                                        }
                                    } else if (nextByte3 == 10) {
                                        sao.setReadPosition(0);
                                        return sb.toString();
                                    } else {
                                        sao.setReadPosition(1);
                                        return sb.toString();
                                    }
                                }
                                sao.setReadPosition(0);
                                return sb.toString();
                            }
                        }
                    }
                }
                this.undecodedChunk.readerIndex(readerIndex);
                throw new NotEnoughDataDecoderException();
            } catch (IndexOutOfBoundsException e) {
                this.undecodedChunk.readerIndex(readerIndex);
                throw new NotEnoughDataDecoderException((Throwable) e);
            }
        } catch (SeekAheadNoBackArrayException e2) {
            return readDelimiterStandard(delimiter);
        }
    }

    private void readFileUploadByteMultipartStandard(String delimiter) throws NotEnoughDataDecoderException, ErrorDataDecoderException {
        int readerIndex = this.undecodedChunk.readerIndex();
        boolean newLine = true;
        int index = 0;
        int lastPosition = this.undecodedChunk.readerIndex();
        boolean found = false;
        while (true) {
            if (!this.undecodedChunk.readable()) {
                break;
            }
            byte nextByte = this.undecodedChunk.readByte();
            if (newLine) {
                if (nextByte == delimiter.codePointAt(index)) {
                    index++;
                    if (delimiter.length() == index) {
                        found = true;
                        break;
                    }
                } else {
                    newLine = false;
                    index = 0;
                    if (nextByte == 13) {
                        if (this.undecodedChunk.readable()) {
                            if (this.undecodedChunk.readByte() == 10) {
                                newLine = true;
                                index = 0;
                                lastPosition = this.undecodedChunk.readerIndex() - 2;
                            } else {
                                lastPosition = this.undecodedChunk.readerIndex() - 1;
                                this.undecodedChunk.readerIndex(lastPosition);
                            }
                        }
                    } else if (nextByte == 10) {
                        newLine = true;
                        index = 0;
                        lastPosition = this.undecodedChunk.readerIndex() - 1;
                    } else {
                        lastPosition = this.undecodedChunk.readerIndex();
                    }
                }
            } else if (nextByte == 13) {
                if (this.undecodedChunk.readable()) {
                    if (this.undecodedChunk.readByte() == 10) {
                        newLine = true;
                        index = 0;
                        lastPosition = this.undecodedChunk.readerIndex() - 2;
                    } else {
                        lastPosition = this.undecodedChunk.readerIndex() - 1;
                        this.undecodedChunk.readerIndex(lastPosition);
                    }
                }
            } else if (nextByte == 10) {
                newLine = true;
                index = 0;
                lastPosition = this.undecodedChunk.readerIndex() - 1;
            } else {
                lastPosition = this.undecodedChunk.readerIndex();
            }
        }
        ChannelBuffer buffer = this.undecodedChunk.slice(readerIndex, lastPosition - readerIndex);
        if (found) {
            try {
                this.currentFileUpload.addContent(buffer, true);
                this.undecodedChunk.readerIndex(lastPosition);
            } catch (IOException e) {
                throw new ErrorDataDecoderException((Throwable) e);
            }
        } else {
            try {
                this.currentFileUpload.addContent(buffer, false);
                this.undecodedChunk.readerIndex(lastPosition);
                throw new NotEnoughDataDecoderException();
            } catch (IOException e2) {
                throw new ErrorDataDecoderException((Throwable) e2);
            }
        }
    }

    private void readFileUploadByteMultipart(String delimiter) throws NotEnoughDataDecoderException, ErrorDataDecoderException {
        try {
            SeekAheadOptimize sao = new SeekAheadOptimize(this.undecodedChunk);
            int readerIndex = this.undecodedChunk.readerIndex();
            boolean newLine = true;
            int index = 0;
            int lastrealpos = sao.pos;
            boolean found = false;
            while (true) {
                if (sao.pos >= sao.limit) {
                    break;
                }
                byte[] bArr = sao.bytes;
                int i = sao.pos;
                sao.pos = i + 1;
                byte nextByte = bArr[i];
                if (newLine) {
                    if (nextByte == delimiter.codePointAt(index)) {
                        index++;
                        if (delimiter.length() == index) {
                            found = true;
                            break;
                        }
                    } else {
                        newLine = false;
                        index = 0;
                        if (nextByte == 13) {
                            if (sao.pos < sao.limit) {
                                byte[] bArr2 = sao.bytes;
                                int i2 = sao.pos;
                                sao.pos = i2 + 1;
                                if (bArr2[i2] == 10) {
                                    newLine = true;
                                    index = 0;
                                    lastrealpos = sao.pos - 2;
                                } else {
                                    sao.pos--;
                                    lastrealpos = sao.pos;
                                }
                            }
                        } else if (nextByte == 10) {
                            newLine = true;
                            index = 0;
                            lastrealpos = sao.pos - 1;
                        } else {
                            lastrealpos = sao.pos;
                        }
                    }
                } else if (nextByte == 13) {
                    if (sao.pos < sao.limit) {
                        byte[] bArr3 = sao.bytes;
                        int i3 = sao.pos;
                        sao.pos = i3 + 1;
                        if (bArr3[i3] == 10) {
                            newLine = true;
                            index = 0;
                            lastrealpos = sao.pos - 2;
                        } else {
                            sao.pos--;
                            lastrealpos = sao.pos;
                        }
                    }
                } else if (nextByte == 10) {
                    newLine = true;
                    index = 0;
                    lastrealpos = sao.pos - 1;
                } else {
                    lastrealpos = sao.pos;
                }
            }
            int lastPosition = sao.getReadPosition(lastrealpos);
            ChannelBuffer buffer = this.undecodedChunk.slice(readerIndex, lastPosition - readerIndex);
            if (found) {
                try {
                    this.currentFileUpload.addContent(buffer, true);
                    this.undecodedChunk.readerIndex(lastPosition);
                } catch (IOException e) {
                    throw new ErrorDataDecoderException((Throwable) e);
                }
            } else {
                try {
                    this.currentFileUpload.addContent(buffer, false);
                    this.undecodedChunk.readerIndex(lastPosition);
                    throw new NotEnoughDataDecoderException();
                } catch (IOException e2) {
                    throw new ErrorDataDecoderException((Throwable) e2);
                }
            }
        } catch (SeekAheadNoBackArrayException e3) {
            readFileUploadByteMultipartStandard(delimiter);
        }
    }

    private void loadFieldMultipartStandard(String delimiter) throws NotEnoughDataDecoderException, ErrorDataDecoderException {
        int readerIndex = this.undecodedChunk.readerIndex();
        boolean newLine = true;
        int index = 0;
        try {
            int lastPosition = this.undecodedChunk.readerIndex();
            boolean found = false;
            while (true) {
                if (!this.undecodedChunk.readable()) {
                    break;
                }
                byte nextByte = this.undecodedChunk.readByte();
                if (newLine) {
                    if (nextByte == delimiter.codePointAt(index)) {
                        index++;
                        if (delimiter.length() == index) {
                            found = true;
                            break;
                        }
                    } else {
                        newLine = false;
                        index = 0;
                        if (nextByte == 13) {
                            if (this.undecodedChunk.readable() && this.undecodedChunk.readByte() == 10) {
                                newLine = true;
                                index = 0;
                                lastPosition = this.undecodedChunk.readerIndex() - 2;
                            }
                        } else if (nextByte == 10) {
                            newLine = true;
                            index = 0;
                            lastPosition = this.undecodedChunk.readerIndex() - 1;
                        } else {
                            lastPosition = this.undecodedChunk.readerIndex();
                        }
                    }
                } else if (nextByte == 13) {
                    if (this.undecodedChunk.readable() && this.undecodedChunk.readByte() == 10) {
                        newLine = true;
                        index = 0;
                        lastPosition = this.undecodedChunk.readerIndex() - 2;
                    }
                } else if (nextByte == 10) {
                    newLine = true;
                    index = 0;
                    lastPosition = this.undecodedChunk.readerIndex() - 1;
                } else {
                    lastPosition = this.undecodedChunk.readerIndex();
                }
            }
            if (found) {
                this.currentAttribute.addContent(this.undecodedChunk.slice(readerIndex, lastPosition - readerIndex), true);
                this.undecodedChunk.readerIndex(lastPosition);
                return;
            }
            this.currentAttribute.addContent(this.undecodedChunk.slice(readerIndex, lastPosition - readerIndex), false);
            this.undecodedChunk.readerIndex(lastPosition);
            throw new NotEnoughDataDecoderException();
        } catch (IOException e) {
            throw new ErrorDataDecoderException((Throwable) e);
        } catch (IOException e2) {
            throw new ErrorDataDecoderException((Throwable) e2);
        } catch (IndexOutOfBoundsException e3) {
            this.undecodedChunk.readerIndex(readerIndex);
            throw new NotEnoughDataDecoderException((Throwable) e3);
        }
    }

    private void loadFieldMultipart(String delimiter) throws NotEnoughDataDecoderException, ErrorDataDecoderException {
        try {
            SeekAheadOptimize sao = new SeekAheadOptimize(this.undecodedChunk);
            int readerIndex = this.undecodedChunk.readerIndex();
            boolean newLine = true;
            int index = 0;
            try {
                int lastrealpos = sao.pos;
                boolean found = false;
                while (true) {
                    if (sao.pos >= sao.limit) {
                        break;
                    }
                    byte[] bArr = sao.bytes;
                    int i = sao.pos;
                    sao.pos = i + 1;
                    byte nextByte = bArr[i];
                    if (newLine) {
                        if (nextByte == delimiter.codePointAt(index)) {
                            index++;
                            if (delimiter.length() == index) {
                                found = true;
                                break;
                            }
                        } else {
                            newLine = false;
                            index = 0;
                            if (nextByte == 13) {
                                if (sao.pos < sao.limit) {
                                    byte[] bArr2 = sao.bytes;
                                    int i2 = sao.pos;
                                    sao.pos = i2 + 1;
                                    if (bArr2[i2] == 10) {
                                        newLine = true;
                                        index = 0;
                                        lastrealpos = sao.pos - 2;
                                    }
                                }
                            } else if (nextByte == 10) {
                                newLine = true;
                                index = 0;
                                lastrealpos = sao.pos - 1;
                            } else {
                                lastrealpos = sao.pos;
                            }
                        }
                    } else if (nextByte == 13) {
                        if (sao.pos < sao.limit) {
                            byte[] bArr3 = sao.bytes;
                            int i3 = sao.pos;
                            sao.pos = i3 + 1;
                            if (bArr3[i3] == 10) {
                                newLine = true;
                                index = 0;
                                lastrealpos = sao.pos - 2;
                            }
                        }
                    } else if (nextByte == 10) {
                        newLine = true;
                        index = 0;
                        lastrealpos = sao.pos - 1;
                    } else {
                        lastrealpos = sao.pos;
                    }
                }
                int lastPosition = sao.getReadPosition(lastrealpos);
                if (found) {
                    this.currentAttribute.addContent(this.undecodedChunk.slice(readerIndex, lastPosition - readerIndex), true);
                    this.undecodedChunk.readerIndex(lastPosition);
                    return;
                }
                this.currentAttribute.addContent(this.undecodedChunk.slice(readerIndex, lastPosition - readerIndex), false);
                this.undecodedChunk.readerIndex(lastPosition);
                throw new NotEnoughDataDecoderException();
            } catch (IOException e) {
                throw new ErrorDataDecoderException((Throwable) e);
            } catch (IOException e2) {
                throw new ErrorDataDecoderException((Throwable) e2);
            } catch (IndexOutOfBoundsException e3) {
                this.undecodedChunk.readerIndex(readerIndex);
                throw new NotEnoughDataDecoderException((Throwable) e3);
            }
        } catch (SeekAheadNoBackArrayException e4) {
            loadFieldMultipartStandard(delimiter);
        }
    }

    private static String cleanString(String field) {
        StringBuilder sb = new StringBuilder(field.length());
        for (int i = 0; i < field.length(); i++) {
            char nextChar = field.charAt(i);
            if (nextChar == ':') {
                sb.append(32);
            } else if (nextChar == ',') {
                sb.append(32);
            } else if (nextChar == '=') {
                sb.append(32);
            } else if (nextChar == ';') {
                sb.append(32);
            } else if (nextChar == 9) {
                sb.append(32);
            } else if (nextChar != '\"') {
                sb.append(nextChar);
            }
        }
        return sb.toString().trim();
    }

    private boolean skipOneLine() {
        if (!this.undecodedChunk.readable()) {
            return false;
        }
        byte nextByte = this.undecodedChunk.readByte();
        if (nextByte == 13) {
            if (!this.undecodedChunk.readable()) {
                this.undecodedChunk.readerIndex(this.undecodedChunk.readerIndex() - 1);
                return false;
            } else if (this.undecodedChunk.readByte() == 10) {
                return true;
            } else {
                this.undecodedChunk.readerIndex(this.undecodedChunk.readerIndex() - 2);
                return false;
            }
        } else if (nextByte == 10) {
            return true;
        } else {
            this.undecodedChunk.readerIndex(this.undecodedChunk.readerIndex() - 1);
            return false;
        }
    }

    private static String[] splitMultipartHeader(String sb) {
        String[] values;
        ArrayList<String> headers = new ArrayList<>(1);
        int nameStart = HttpPostBodyUtil.findNonWhitespace(sb, 0);
        int nameEnd = nameStart;
        while (nameEnd < sb.length()) {
            char ch = sb.charAt(nameEnd);
            if (ch == ':' || Character.isWhitespace(ch)) {
                break;
            }
            nameEnd++;
        }
        int colonEnd = nameEnd;
        while (true) {
            if (colonEnd >= sb.length()) {
                break;
            } else if (sb.charAt(colonEnd) == ':') {
                colonEnd++;
                break;
            } else {
                colonEnd++;
            }
        }
        int valueStart = HttpPostBodyUtil.findNonWhitespace(sb, colonEnd);
        int valueEnd = HttpPostBodyUtil.findEndOfString(sb);
        headers.add(sb.substring(nameStart, nameEnd));
        String svalue = sb.substring(valueStart, valueEnd);
        if (svalue.indexOf(59) >= 0) {
            values = StringUtil.split(svalue, ';');
        } else {
            values = StringUtil.split(svalue, ',');
        }
        for (String value : values) {
            headers.add(value.trim());
        }
        String[] array = new String[headers.size()];
        for (int i = 0; i < headers.size(); i++) {
            array[i] = headers.get(i);
        }
        return array;
    }
}