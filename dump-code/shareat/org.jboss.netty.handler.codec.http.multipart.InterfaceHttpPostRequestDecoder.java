package org.jboss.netty.handler.codec.http.multipart;

import java.util.List;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.EndOfDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.ErrorDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.NotEnoughDataDecoderException;

public interface InterfaceHttpPostRequestDecoder {
    void cleanFiles();

    InterfaceHttpData getBodyHttpData(String str) throws NotEnoughDataDecoderException;

    List<InterfaceHttpData> getBodyHttpDatas() throws NotEnoughDataDecoderException;

    List<InterfaceHttpData> getBodyHttpDatas(String str) throws NotEnoughDataDecoderException;

    boolean hasNext() throws EndOfDataDecoderException;

    boolean isMultipart();

    InterfaceHttpData next() throws EndOfDataDecoderException;

    void offer(HttpChunk httpChunk) throws ErrorDataDecoderException;

    void removeHttpDataFromClean(InterfaceHttpData interfaceHttpData);
}