package org.jboss.netty.handler.codec.http.multipart;

import com.facebook.share.internal.ShareConstants;
import java.nio.charset.Charset;
import java.util.List;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpConstants;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.util.internal.StringUtil;

public class HttpPostRequestDecoder implements InterfaceHttpPostRequestDecoder {
    private final InterfaceHttpPostRequestDecoder decoder;

    @Deprecated
    public static class IncompatibleDataDecoderException extends Exception {
        private static final long serialVersionUID = -953268047926250267L;

        public IncompatibleDataDecoderException() {
        }

        public IncompatibleDataDecoderException(String msg) {
            super(msg);
        }

        public IncompatibleDataDecoderException(Throwable cause) {
            super(cause);
        }

        public IncompatibleDataDecoderException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }

    public static class EndOfDataDecoderException extends Exception {
        private static final long serialVersionUID = 1336267941020800769L;
    }

    public static class ErrorDataDecoderException extends Exception {
        private static final long serialVersionUID = 5020247425493164465L;

        public ErrorDataDecoderException() {
        }

        public ErrorDataDecoderException(String msg) {
            super(msg);
        }

        public ErrorDataDecoderException(Throwable cause) {
            super(cause);
        }

        public ErrorDataDecoderException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }

    protected enum MultiPartStatus {
        NOTSTARTED,
        PREAMBLE,
        HEADERDELIMITER,
        DISPOSITION,
        FIELD,
        FILEUPLOAD,
        MIXEDPREAMBLE,
        MIXEDDELIMITER,
        MIXEDDISPOSITION,
        MIXEDFILEUPLOAD,
        MIXEDCLOSEDELIMITER,
        CLOSEDELIMITER,
        PREEPILOGUE,
        EPILOGUE
    }

    public static class NotEnoughDataDecoderException extends Exception {
        private static final long serialVersionUID = -7846841864603865638L;

        public NotEnoughDataDecoderException() {
        }

        public NotEnoughDataDecoderException(String msg) {
            super(msg);
        }

        public NotEnoughDataDecoderException(Throwable cause) {
            super(cause);
        }

        public NotEnoughDataDecoderException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }

    public HttpPostRequestDecoder(HttpRequest request) throws ErrorDataDecoderException, IncompatibleDataDecoderException {
        this(new DefaultHttpDataFactory(16384), request, HttpConstants.DEFAULT_CHARSET);
    }

    public HttpPostRequestDecoder(HttpDataFactory factory, HttpRequest request) throws ErrorDataDecoderException, IncompatibleDataDecoderException {
        this(factory, request, HttpConstants.DEFAULT_CHARSET);
    }

    public HttpPostRequestDecoder(HttpDataFactory factory, HttpRequest request, Charset charset) throws ErrorDataDecoderException, IncompatibleDataDecoderException {
        if (factory == null) {
            throw new NullPointerException("factory");
        } else if (request == null) {
            throw new NullPointerException(ShareConstants.WEB_DIALOG_RESULT_PARAM_REQUEST_ID);
        } else if (charset == null) {
            throw new NullPointerException("charset");
        } else if (isMultipart(request)) {
            this.decoder = new HttpPostMultipartRequestDecoder(factory, request, charset);
        } else {
            this.decoder = new HttpPostStandardRequestDecoder(factory, request, charset);
        }
    }

    public static boolean isMultipart(HttpRequest request) throws ErrorDataDecoderException {
        if (!request.headers().contains("Content-Type") || getMultipartDataBoundary(request.headers().get("Content-Type")) == null) {
            return false;
        }
        return true;
    }

    protected static String[] getMultipartDataBoundary(String contentType) throws ErrorDataDecoderException {
        int mrank;
        int crank;
        String[] headerContentType = splitHeaderContentType(contentType);
        if (!headerContentType[0].toLowerCase().startsWith(Values.MULTIPART_FORM_DATA)) {
            return null;
        }
        if (headerContentType[1].toLowerCase().startsWith(Values.BOUNDARY.toString())) {
            mrank = 1;
            crank = 2;
        } else if (!headerContentType[2].toLowerCase().startsWith(Values.BOUNDARY.toString())) {
            return null;
        } else {
            mrank = 2;
            crank = 1;
        }
        String[] boundary = StringUtil.split(headerContentType[mrank], '=');
        if (boundary.length != 2) {
            throw new ErrorDataDecoderException((String) "Needs a boundary value");
        }
        if (headerContentType[crank].toLowerCase().startsWith("charset".toString())) {
            String[] charset = StringUtil.split(headerContentType[crank], '=');
            if (charset.length > 1) {
                return new String[]{"--" + boundary[1], charset[1]};
            }
        }
        return new String[]{"--" + boundary[1]};
    }

    public boolean isMultipart() {
        return this.decoder.isMultipart();
    }

    public List<InterfaceHttpData> getBodyHttpDatas() throws NotEnoughDataDecoderException {
        return this.decoder.getBodyHttpDatas();
    }

    public List<InterfaceHttpData> getBodyHttpDatas(String name) throws NotEnoughDataDecoderException {
        return this.decoder.getBodyHttpDatas(name);
    }

    public InterfaceHttpData getBodyHttpData(String name) throws NotEnoughDataDecoderException {
        return this.decoder.getBodyHttpData(name);
    }

    public void offer(HttpChunk chunk) throws ErrorDataDecoderException {
        this.decoder.offer(chunk);
    }

    public boolean hasNext() throws EndOfDataDecoderException {
        return this.decoder.hasNext();
    }

    public InterfaceHttpData next() throws EndOfDataDecoderException {
        return this.decoder.next();
    }

    public void cleanFiles() {
        this.decoder.cleanFiles();
    }

    public void removeHttpDataFromClean(InterfaceHttpData data) {
        this.decoder.removeHttpDataFromClean(data);
    }

    private static String[] splitHeaderContentType(String sb) {
        int aStart = HttpPostBodyUtil.findNonWhitespace(sb, 0);
        int aEnd = sb.indexOf(59);
        if (aEnd == -1) {
            return new String[]{sb, "", ""};
        }
        int bStart = HttpPostBodyUtil.findNonWhitespace(sb, aEnd + 1);
        if (sb.charAt(aEnd - 1) == ' ') {
            aEnd--;
        }
        int bEnd = sb.indexOf(59, bStart);
        if (bEnd == -1) {
            return new String[]{sb.substring(aStart, aEnd), sb.substring(bStart, HttpPostBodyUtil.findEndOfString(sb)), ""};
        }
        int cStart = HttpPostBodyUtil.findNonWhitespace(sb, bEnd + 1);
        if (sb.charAt(bEnd - 1) == ' ') {
            bEnd--;
        }
        return new String[]{sb.substring(aStart, aEnd), sb.substring(bStart, bEnd), sb.substring(cStart, HttpPostBodyUtil.findEndOfString(sb))};
    }
}