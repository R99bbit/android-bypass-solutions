package com.ning.http.util;

import com.kakao.util.helper.CommonProtocol;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.ByteArrayPart;
import com.ning.http.client.FilePart;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseBodyPartsInputStream;
import com.ning.http.client.Part;
import com.ning.http.client.Request;
import com.ning.http.client.StringPart;
import com.ning.http.multipart.ByteArrayPartSource;
import com.ning.http.multipart.MultipartRequestEntity;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

public class AsyncHttpProviderUtils {
    public static final String DEFAULT_CHARSET = "ISO-8859-1";
    static final byte[] EMPTY_BYTE_ARRAY = "".getBytes();

    public static final void validateSupportedScheme(URI uri) {
        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase(CommonProtocol.URL_SCHEME) && !scheme.equalsIgnoreCase("ws") && !scheme.equalsIgnoreCase("wss"))) {
            throw new IllegalArgumentException("The URI scheme, of the URI " + uri + ", must be equal (ignoring case) to 'http', 'https', 'ws', or 'wss'");
        }
    }

    public static final URI createUri(String u) {
        URI uri = URI.create(u);
        validateSupportedScheme(uri);
        String path = uri.getPath();
        if (path == null) {
            throw new IllegalArgumentException("The URI path, of the URI " + uri + ", must be non-null");
        } else if (MiscUtil.isNonEmpty(path) && path.charAt(0) != '/') {
            throw new IllegalArgumentException("The URI path, of the URI " + uri + ". must start with a '/'");
        } else if (!MiscUtil.isNonEmpty(path)) {
            return URI.create(u + "/");
        } else {
            return uri;
        }
    }

    public static String getBaseUrl(String url) {
        return getBaseUrl(createUri(url));
    }

    public static final String getBaseUrl(URI uri) {
        String url = uri.getScheme() + "://" + uri.getAuthority();
        if (uri.getPort() != -1) {
            return url;
        }
        return url + ":" + getPort(uri);
    }

    public static final String getAuthority(URI uri) {
        String url = uri.getAuthority();
        if (uri.getPort() != -1) {
            return url;
        }
        return url + ":" + getPort(uri);
    }

    public static final String contentToString(List<HttpResponseBodyPart> bodyParts, String charset) throws UnsupportedEncodingException {
        return new String(contentToByte(bodyParts), charset);
    }

    public static final byte[] contentToByte(List<HttpResponseBodyPart> bodyParts) throws UnsupportedEncodingException {
        if (bodyParts.size() == 1) {
            return bodyParts.get(0).getBodyPartBytes();
        }
        int size = 0;
        for (HttpResponseBodyPart body : bodyParts) {
            size += body.getBodyPartBytes().length;
        }
        byte[] bytes = new byte[size];
        int offset = 0;
        for (HttpResponseBodyPart body2 : bodyParts) {
            byte[] bodyBytes = body2.getBodyPartBytes();
            System.arraycopy(bodyBytes, 0, bytes, offset, bodyBytes.length);
            offset += bodyBytes.length;
        }
        return bytes;
    }

    public static final InputStream contentToInputStream(List<HttpResponseBodyPart> bodyParts) throws UnsupportedEncodingException {
        return bodyParts.isEmpty() ? new ByteArrayInputStream(EMPTY_BYTE_ARRAY) : new HttpResponseBodyPartsInputStream(bodyParts);
    }

    public static final String getHost(URI uri) {
        String host = uri.getHost();
        if (host == null) {
            return uri.getAuthority();
        }
        return host;
    }

    public static final URI getRedirectUri(URI uri, String location) {
        URI locationURI;
        if (location == null) {
            throw new IllegalArgumentException("URI " + uri + " was redirected to null location");
        }
        try {
            locationURI = new URI(location);
        } catch (URISyntaxException e) {
            String[] parts = location.split("\\?");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Don't know how to turn this location into a proper URI:" + location, e);
            }
            StringBuilder properUrl = new StringBuilder(location.length()).append(parts[0]).append("?");
            String[] queryParams = parts[1].split("&");
            for (int i = 0; i < queryParams.length; i++) {
                String queryParam = queryParams[i];
                if (i != 0) {
                    properUrl.append("&");
                }
                String[] nameValue = queryParam.split("=", 2);
                UTF8UrlEncoder.appendEncoded(properUrl, nameValue[0]);
                if (nameValue.length == 2) {
                    properUrl.append("=");
                    UTF8UrlEncoder.appendEncoded(properUrl, nameValue[1]);
                }
            }
            locationURI = URI.create(properUrl.toString());
        }
        URI redirectUri = uri.resolve(locationURI);
        String scheme = redirectUri.getScheme();
        if (scheme != null && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase(CommonProtocol.URL_SCHEME) || scheme.equals("ws") || scheme.equals("wss"))) {
            return redirectUri.normalize();
        }
        throw new IllegalArgumentException("The URI scheme, of the URI " + redirectUri + ", must be equal (ignoring case) to 'ws, 'wss', 'http', or 'https'");
    }

    public static final int getPort(URI uri) {
        int port = uri.getPort();
        if (port == -1) {
            return (uri.getScheme().equals("http") || uri.getScheme().equals("ws")) ? 80 : 443;
        }
        return port;
    }

    public static final MultipartRequestEntity createMultipartRequestEntity(List<Part> params, FluentCaseInsensitiveStringsMap requestHeaders) throws FileNotFoundException {
        com.ning.http.multipart.Part[] parts = new com.ning.http.multipart.Part[params.size()];
        int i = 0;
        for (Part part : params) {
            if (part instanceof com.ning.http.multipart.Part) {
                parts[i] = (com.ning.http.multipart.Part) part;
            } else if (part instanceof StringPart) {
                StringPart stringPart = (StringPart) part;
                parts[i] = new com.ning.http.multipart.StringPart(part.getName(), stringPart.getValue(), stringPart.getCharset());
            } else if (part instanceof FilePart) {
                FilePart filePart = (FilePart) part;
                parts[i] = new com.ning.http.multipart.FilePart(part.getName(), filePart.getFile(), filePart.getMimeType(), filePart.getCharSet());
            } else if (part instanceof ByteArrayPart) {
                ByteArrayPart byteArrayPart = (ByteArrayPart) part;
                parts[i] = new com.ning.http.multipart.FilePart(part.getName(), new ByteArrayPartSource(byteArrayPart.getFileName(), byteArrayPart.getData()), byteArrayPart.getMimeType(), byteArrayPart.getCharSet());
            } else if (part == null) {
                throw new NullPointerException("Part cannot be null");
            } else {
                throw new IllegalArgumentException(String.format("Unsupported part type for multipart parameter %s", new Object[]{part.getName()}));
            }
            i++;
        }
        return new MultipartRequestEntity(parts, requestHeaders);
    }

    public static final byte[] readFully(InputStream in, int[] lengthWrapper) throws IOException {
        byte[] b = new byte[Math.max(512, in.available())];
        int offset = 0;
        while (true) {
            int left = b.length - offset;
            int count = in.read(b, offset, left);
            if (count < 0) {
                lengthWrapper[0] = offset;
                return b;
            }
            offset += count;
            if (count == left) {
                b = doubleUp(b);
            }
        }
    }

    private static byte[] doubleUp(byte[] b) {
        int len = b.length;
        byte[] b2 = new byte[(len + len)];
        System.arraycopy(b, 0, b2, 0, len);
        return b2;
    }

    public static String constructUserAgent(Class<? extends AsyncHttpProvider> httpProvider) {
        return "AsyncHttpClient/1.0" + " " + "(" + httpProvider.getSimpleName() + " - " + System.getProperty("os.name") + " - " + System.getProperty("os.version") + " - " + System.getProperty("java.version") + " - " + Runtime.getRuntime().availableProcessors() + " core(s))";
    }

    public static String parseCharset(String contentType) {
        String[] arr$;
        for (String part : contentType.split(";")) {
            if (part.trim().startsWith("charset=")) {
                String[] val = part.split("=");
                if (val.length > 1) {
                    return val[1].trim().replaceAll("\"", "").replaceAll("'", "");
                }
            }
        }
        return null;
    }

    public static String keepAliveHeaderValue(AsyncHttpClientConfig config) {
        return config.getAllowPoolingConnection() ? "keep-alive" : "close";
    }

    public static int requestTimeout(AsyncHttpClientConfig config, Request request) {
        return (request.getPerRequestConfig() == null || request.getPerRequestConfig().getRequestTimeoutInMs() == 0) ? config.getRequestTimeoutInMs() : request.getPerRequestConfig().getRequestTimeoutInMs();
    }
}