package org.jboss.netty.handler.codec.http.multipart;

import com.facebook.share.internal.ShareConstants;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpConstants;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.EndOfDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.ErrorDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.IncompatibleDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.NotEnoughDataDecoderException;
import org.jboss.netty.util.internal.CaseIgnoringComparator;

public class HttpPostStandardRequestDecoder implements InterfaceHttpPostRequestDecoder {
    private final List<InterfaceHttpData> bodyListHttpData;
    private int bodyListHttpDataRank;
    private final Map<String, List<InterfaceHttpData>> bodyMapHttpData;
    private final Charset charset;
    private Attribute currentAttribute;
    private MultiPartStatus currentStatus;
    private final HttpDataFactory factory;
    private boolean isLastChunk;
    private final HttpRequest request;
    private ChannelBuffer undecodedChunk;

    public HttpPostStandardRequestDecoder(HttpRequest request2) throws ErrorDataDecoderException, IncompatibleDataDecoderException {
        this(new DefaultHttpDataFactory(16384), request2, HttpConstants.DEFAULT_CHARSET);
    }

    public HttpPostStandardRequestDecoder(HttpDataFactory factory2, HttpRequest request2) throws ErrorDataDecoderException, IncompatibleDataDecoderException {
        this(factory2, request2, HttpConstants.DEFAULT_CHARSET);
    }

    public HttpPostStandardRequestDecoder(HttpDataFactory factory2, HttpRequest request2, Charset charset2) throws ErrorDataDecoderException, IncompatibleDataDecoderException {
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
            if (!this.request.isChunked()) {
                this.undecodedChunk = this.request.getContent();
                this.isLastChunk = true;
                parseBody();
            }
        }
    }

    public boolean isMultipart() {
        return false;
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
            parseBodyAttributes();
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

    private void parseBodyAttributesStandard() throws ErrorDataDecoderException {
        int firstpos = this.undecodedChunk.readerIndex();
        int currentpos = firstpos;
        if (this.currentStatus == MultiPartStatus.NOTSTARTED) {
            this.currentStatus = MultiPartStatus.DISPOSITION;
        }
        boolean contRead = true;
        while (this.undecodedChunk.readable() && contRead) {
            try {
                char read = (char) this.undecodedChunk.readUnsignedByte();
                currentpos++;
                switch (this.currentStatus) {
                    case DISPOSITION:
                        if (read != '=') {
                            if (read != '&') {
                                break;
                            } else {
                                this.currentStatus = MultiPartStatus.DISPOSITION;
                                this.currentAttribute = this.factory.createAttribute(this.request, decodeAttribute(this.undecodedChunk.toString(firstpos, (currentpos - 1) - firstpos, this.charset), this.charset));
                                this.currentAttribute.setValue("");
                                addHttpData(this.currentAttribute);
                                this.currentAttribute = null;
                                firstpos = currentpos;
                                contRead = true;
                                break;
                            }
                        } else {
                            this.currentStatus = MultiPartStatus.FIELD;
                            this.currentAttribute = this.factory.createAttribute(this.request, decodeAttribute(this.undecodedChunk.toString(firstpos, (currentpos - 1) - firstpos, this.charset), this.charset));
                            firstpos = currentpos;
                            break;
                        }
                    case FIELD:
                        if (read != '&') {
                            if (read != 13) {
                                if (read != 10) {
                                    break;
                                } else {
                                    this.currentStatus = MultiPartStatus.PREEPILOGUE;
                                    setFinalBuffer(this.undecodedChunk.slice(firstpos, (currentpos - 1) - firstpos));
                                    firstpos = currentpos;
                                    contRead = false;
                                    break;
                                }
                            } else if (!this.undecodedChunk.readable()) {
                                currentpos--;
                                break;
                            } else {
                                currentpos++;
                                if (((char) this.undecodedChunk.readUnsignedByte()) == 10) {
                                    this.currentStatus = MultiPartStatus.PREEPILOGUE;
                                    setFinalBuffer(this.undecodedChunk.slice(firstpos, (currentpos - 2) - firstpos));
                                    firstpos = currentpos;
                                    contRead = false;
                                    break;
                                } else {
                                    throw new ErrorDataDecoderException((String) "Bad end of line");
                                }
                            }
                        } else {
                            this.currentStatus = MultiPartStatus.DISPOSITION;
                            setFinalBuffer(this.undecodedChunk.slice(firstpos, (currentpos - 1) - firstpos));
                            firstpos = currentpos;
                            contRead = true;
                            break;
                        }
                    default:
                        contRead = false;
                        break;
                }
            } catch (ErrorDataDecoderException e) {
                this.undecodedChunk.readerIndex(firstpos);
                throw e;
            } catch (IOException e2) {
                this.undecodedChunk.readerIndex(firstpos);
                throw new ErrorDataDecoderException((Throwable) e2);
            }
        }
        if (this.isLastChunk && this.currentAttribute != null) {
            int ampersandpos = currentpos;
            if (ampersandpos > firstpos) {
                setFinalBuffer(this.undecodedChunk.slice(firstpos, ampersandpos - firstpos));
            } else if (!this.currentAttribute.isCompleted()) {
                setFinalBuffer(ChannelBuffers.EMPTY_BUFFER);
            }
            int firstpos2 = currentpos;
            this.currentStatus = MultiPartStatus.EPILOGUE;
        } else if (!contRead) {
        } else {
            if (this.currentAttribute != null) {
                if (this.currentStatus == MultiPartStatus.FIELD) {
                    this.currentAttribute.addContent(this.undecodedChunk.slice(firstpos, currentpos - firstpos), false);
                    firstpos = currentpos;
                }
                this.undecodedChunk.readerIndex(firstpos);
            }
        }
    }

    private void parseBodyAttributes() throws ErrorDataDecoderException {
        try {
            SeekAheadOptimize sao = new SeekAheadOptimize(this.undecodedChunk);
            int firstpos = this.undecodedChunk.readerIndex();
            int currentpos = firstpos;
            if (this.currentStatus == MultiPartStatus.NOTSTARTED) {
                this.currentStatus = MultiPartStatus.DISPOSITION;
            }
            boolean contRead = true;
            while (true) {
                try {
                    if (sao.pos < sao.limit) {
                        byte[] bArr = sao.bytes;
                        int i = sao.pos;
                        sao.pos = i + 1;
                        char read = (char) (bArr[i] & 255);
                        currentpos++;
                        switch (this.currentStatus) {
                            case DISPOSITION:
                                if (read != '=') {
                                    if (read != '&') {
                                        break;
                                    } else {
                                        this.currentStatus = MultiPartStatus.DISPOSITION;
                                        this.currentAttribute = this.factory.createAttribute(this.request, decodeAttribute(this.undecodedChunk.toString(firstpos, (currentpos - 1) - firstpos, this.charset), this.charset));
                                        this.currentAttribute.setValue("");
                                        addHttpData(this.currentAttribute);
                                        this.currentAttribute = null;
                                        firstpos = currentpos;
                                        contRead = true;
                                        break;
                                    }
                                } else {
                                    this.currentStatus = MultiPartStatus.FIELD;
                                    this.currentAttribute = this.factory.createAttribute(this.request, decodeAttribute(this.undecodedChunk.toString(firstpos, (currentpos - 1) - firstpos, this.charset), this.charset));
                                    firstpos = currentpos;
                                    continue;
                                }
                            case FIELD:
                                if (read != '&') {
                                    if (read != 13) {
                                        if (read != 10) {
                                            break;
                                        } else {
                                            this.currentStatus = MultiPartStatus.PREEPILOGUE;
                                            sao.setReadPosition(0);
                                            setFinalBuffer(this.undecodedChunk.slice(firstpos, (currentpos - 1) - firstpos));
                                            firstpos = currentpos;
                                            contRead = false;
                                            break;
                                        }
                                    } else if (sao.pos >= sao.limit) {
                                        if (sao.limit <= 0) {
                                            break;
                                        } else {
                                            currentpos--;
                                            break;
                                        }
                                    } else {
                                        byte[] bArr2 = sao.bytes;
                                        int i2 = sao.pos;
                                        sao.pos = i2 + 1;
                                        currentpos++;
                                        if (((char) (bArr2[i2] & 255)) == 10) {
                                            this.currentStatus = MultiPartStatus.PREEPILOGUE;
                                            sao.setReadPosition(0);
                                            setFinalBuffer(this.undecodedChunk.slice(firstpos, (currentpos - 2) - firstpos));
                                            firstpos = currentpos;
                                            contRead = false;
                                            break;
                                        } else {
                                            sao.setReadPosition(0);
                                            throw new ErrorDataDecoderException((String) "Bad end of line");
                                        }
                                    }
                                } else {
                                    this.currentStatus = MultiPartStatus.DISPOSITION;
                                    setFinalBuffer(this.undecodedChunk.slice(firstpos, (currentpos - 1) - firstpos));
                                    firstpos = currentpos;
                                    contRead = true;
                                    continue;
                                }
                            default:
                                sao.setReadPosition(0);
                                contRead = false;
                                break;
                        }
                    }
                } catch (ErrorDataDecoderException e) {
                    this.undecodedChunk.readerIndex(firstpos);
                    throw e;
                } catch (IOException e2) {
                    this.undecodedChunk.readerIndex(firstpos);
                    throw new ErrorDataDecoderException((Throwable) e2);
                }
            }
            if (this.isLastChunk && this.currentAttribute != null) {
                int ampersandpos = currentpos;
                if (ampersandpos > firstpos) {
                    setFinalBuffer(this.undecodedChunk.slice(firstpos, ampersandpos - firstpos));
                } else if (!this.currentAttribute.isCompleted()) {
                    setFinalBuffer(ChannelBuffers.EMPTY_BUFFER);
                }
                int firstpos2 = currentpos;
                this.currentStatus = MultiPartStatus.EPILOGUE;
            } else if (!contRead) {
            } else {
                if (this.currentAttribute != null) {
                    if (this.currentStatus == MultiPartStatus.FIELD) {
                        this.currentAttribute.addContent(this.undecodedChunk.slice(firstpos, currentpos - firstpos), false);
                        firstpos = currentpos;
                    }
                    this.undecodedChunk.readerIndex(firstpos);
                }
            }
        } catch (SeekAheadNoBackArrayException e3) {
            parseBodyAttributesStandard();
        }
    }

    private void setFinalBuffer(ChannelBuffer buffer) throws ErrorDataDecoderException, IOException {
        this.currentAttribute.addContent(buffer, true);
        this.currentAttribute.setValue(decodeAttribute(this.currentAttribute.getChannelBuffer().toString(this.charset), this.charset));
        addHttpData(this.currentAttribute);
        this.currentAttribute = null;
    }

    private static String decodeAttribute(String s, Charset charset2) throws ErrorDataDecoderException {
        if (s == null) {
            return "";
        }
        try {
            return URLDecoder.decode(s, charset2.name());
        } catch (UnsupportedEncodingException e) {
            throw new ErrorDataDecoderException(charset2.toString(), e);
        } catch (IllegalArgumentException e2) {
            throw new ErrorDataDecoderException("Bad string: '" + s + '\'', e2);
        }
    }

    public void cleanFiles() {
        this.factory.cleanRequestHttpDatas(this.request);
    }

    public void removeHttpDataFromClean(InterfaceHttpData data) {
        this.factory.removeHttpDataFromClean(this.request, data);
    }
}