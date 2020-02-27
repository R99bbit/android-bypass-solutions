package org.jboss.netty.handler.codec.http;

public class HttpResponseStatus implements Comparable<HttpResponseStatus> {
    public static final HttpResponseStatus ACCEPTED = new HttpResponseStatus(202, "Accepted");
    public static final HttpResponseStatus BAD_GATEWAY = new HttpResponseStatus(502, "Bad Gateway");
    public static final HttpResponseStatus BAD_REQUEST = new HttpResponseStatus(400, "Bad Request");
    public static final HttpResponseStatus CONFLICT = new HttpResponseStatus(409, "Conflict");
    public static final HttpResponseStatus CONTINUE = new HttpResponseStatus(100, "Continue");
    public static final HttpResponseStatus CREATED = new HttpResponseStatus(201, "Created");
    public static final HttpResponseStatus EXPECTATION_FAILED = new HttpResponseStatus(417, "Expectation Failed");
    public static final HttpResponseStatus FAILED_DEPENDENCY = new HttpResponseStatus(424, "Failed Dependency");
    public static final HttpResponseStatus FORBIDDEN = new HttpResponseStatus(403, "Forbidden");
    public static final HttpResponseStatus FOUND = new HttpResponseStatus(302, "Found");
    public static final HttpResponseStatus GATEWAY_TIMEOUT = new HttpResponseStatus(504, "Gateway Timeout");
    public static final HttpResponseStatus GONE = new HttpResponseStatus(410, "Gone");
    public static final HttpResponseStatus HTTP_VERSION_NOT_SUPPORTED = new HttpResponseStatus(505, "HTTP Version Not Supported");
    public static final HttpResponseStatus INSUFFICIENT_STORAGE = new HttpResponseStatus(507, "Insufficient Storage");
    public static final HttpResponseStatus INTERNAL_SERVER_ERROR = new HttpResponseStatus(500, "Internal Server Error");
    public static final HttpResponseStatus LENGTH_REQUIRED = new HttpResponseStatus(411, "Length Required");
    public static final HttpResponseStatus LOCKED = new HttpResponseStatus(423, "Locked");
    public static final HttpResponseStatus METHOD_NOT_ALLOWED = new HttpResponseStatus(405, "Method Not Allowed");
    public static final HttpResponseStatus MOVED_PERMANENTLY = new HttpResponseStatus(301, "Moved Permanently");
    public static final HttpResponseStatus MULTIPLE_CHOICES = new HttpResponseStatus(300, "Multiple Choices");
    public static final HttpResponseStatus MULTI_STATUS = new HttpResponseStatus(207, "Multi-Status");
    public static final HttpResponseStatus NON_AUTHORITATIVE_INFORMATION = new HttpResponseStatus(203, "Non-Authoritative Information");
    public static final HttpResponseStatus NOT_ACCEPTABLE = new HttpResponseStatus(406, "Not Acceptable");
    public static final HttpResponseStatus NOT_EXTENDED = new HttpResponseStatus(510, "Not Extended");
    public static final HttpResponseStatus NOT_FOUND = new HttpResponseStatus(404, "Not Found");
    public static final HttpResponseStatus NOT_IMPLEMENTED = new HttpResponseStatus(501, "Not Implemented");
    public static final HttpResponseStatus NOT_MODIFIED = new HttpResponseStatus(304, "Not Modified");
    public static final HttpResponseStatus NO_CONTENT = new HttpResponseStatus(204, "No Content");
    public static final HttpResponseStatus OK = new HttpResponseStatus(200, "OK");
    public static final HttpResponseStatus PARTIAL_CONTENT = new HttpResponseStatus(206, "Partial Content");
    public static final HttpResponseStatus PAYMENT_REQUIRED = new HttpResponseStatus(402, "Payment Required");
    public static final HttpResponseStatus PRECONDITION_FAILED = new HttpResponseStatus(412, "Precondition Failed");
    public static final HttpResponseStatus PROCESSING = new HttpResponseStatus(102, "Processing");
    public static final HttpResponseStatus PROXY_AUTHENTICATION_REQUIRED = new HttpResponseStatus(407, "Proxy Authentication Required");
    public static final HttpResponseStatus REQUESTED_RANGE_NOT_SATISFIABLE = new HttpResponseStatus(416, "Requested Range Not Satisfiable");
    public static final HttpResponseStatus REQUEST_ENTITY_TOO_LARGE = new HttpResponseStatus(413, "Request Entity Too Large");
    public static final HttpResponseStatus REQUEST_HEADER_FIELDS_TOO_LARGE = new HttpResponseStatus(431, "Request Header Fields Too Large");
    public static final HttpResponseStatus REQUEST_TIMEOUT = new HttpResponseStatus(408, "Request Timeout");
    public static final HttpResponseStatus REQUEST_URI_TOO_LONG = new HttpResponseStatus(414, "Request-URI Too Long");
    public static final HttpResponseStatus RESET_CONTENT = new HttpResponseStatus(205, "Reset Content");
    public static final HttpResponseStatus SEE_OTHER = new HttpResponseStatus(303, "See Other");
    public static final HttpResponseStatus SERVICE_UNAVAILABLE = new HttpResponseStatus(503, "Service Unavailable");
    public static final HttpResponseStatus SWITCHING_PROTOCOLS = new HttpResponseStatus(101, "Switching Protocols");
    public static final HttpResponseStatus TEMPORARY_REDIRECT = new HttpResponseStatus(307, "Temporary Redirect");
    public static final HttpResponseStatus UNAUTHORIZED = new HttpResponseStatus(401, "Unauthorized");
    public static final HttpResponseStatus UNORDERED_COLLECTION = new HttpResponseStatus(425, "Unordered Collection");
    public static final HttpResponseStatus UNPROCESSABLE_ENTITY = new HttpResponseStatus(422, "Unprocessable Entity");
    public static final HttpResponseStatus UNSUPPORTED_MEDIA_TYPE = new HttpResponseStatus(415, "Unsupported Media Type");
    public static final HttpResponseStatus UPGRADE_REQUIRED = new HttpResponseStatus(426, "Upgrade Required");
    public static final HttpResponseStatus USE_PROXY = new HttpResponseStatus(305, "Use Proxy");
    public static final HttpResponseStatus VARIANT_ALSO_NEGOTIATES = new HttpResponseStatus(506, "Variant Also Negotiates");
    private final int code;
    private final String reasonPhrase;

    public static HttpResponseStatus valueOf(int code2) {
        String reasonPhrase2;
        switch (code2) {
            case 100:
                return CONTINUE;
            case 101:
                return SWITCHING_PROTOCOLS;
            case 102:
                return PROCESSING;
            case 200:
                return OK;
            case 201:
                return CREATED;
            case 202:
                return ACCEPTED;
            case 203:
                return NON_AUTHORITATIVE_INFORMATION;
            case 204:
                return NO_CONTENT;
            case 205:
                return RESET_CONTENT;
            case 206:
                return PARTIAL_CONTENT;
            case 207:
                return MULTI_STATUS;
            case 300:
                return MULTIPLE_CHOICES;
            case 301:
                return MOVED_PERMANENTLY;
            case 302:
                return FOUND;
            case 303:
                return SEE_OTHER;
            case 304:
                return NOT_MODIFIED;
            case 305:
                return USE_PROXY;
            case 307:
                return TEMPORARY_REDIRECT;
            case 400:
                return BAD_REQUEST;
            case 401:
                return UNAUTHORIZED;
            case 402:
                return PAYMENT_REQUIRED;
            case 403:
                return FORBIDDEN;
            case 404:
                return NOT_FOUND;
            case 405:
                return METHOD_NOT_ALLOWED;
            case 406:
                return NOT_ACCEPTABLE;
            case 407:
                return PROXY_AUTHENTICATION_REQUIRED;
            case 408:
                return REQUEST_TIMEOUT;
            case 409:
                return CONFLICT;
            case 410:
                return GONE;
            case 411:
                return LENGTH_REQUIRED;
            case 412:
                return PRECONDITION_FAILED;
            case 413:
                return REQUEST_ENTITY_TOO_LARGE;
            case 414:
                return REQUEST_URI_TOO_LONG;
            case 415:
                return UNSUPPORTED_MEDIA_TYPE;
            case 416:
                return REQUESTED_RANGE_NOT_SATISFIABLE;
            case 417:
                return EXPECTATION_FAILED;
            case 422:
                return UNPROCESSABLE_ENTITY;
            case 423:
                return LOCKED;
            case 424:
                return FAILED_DEPENDENCY;
            case 425:
                return UNORDERED_COLLECTION;
            case 426:
                return UPGRADE_REQUIRED;
            case 500:
                return INTERNAL_SERVER_ERROR;
            case 501:
                return NOT_IMPLEMENTED;
            case 502:
                return BAD_GATEWAY;
            case 503:
                return SERVICE_UNAVAILABLE;
            case 504:
                return GATEWAY_TIMEOUT;
            case 505:
                return HTTP_VERSION_NOT_SUPPORTED;
            case 506:
                return VARIANT_ALSO_NEGOTIATES;
            case 507:
                return INSUFFICIENT_STORAGE;
            case 510:
                return NOT_EXTENDED;
            default:
                if (code2 < 100) {
                    reasonPhrase2 = "Unknown Status";
                } else if (code2 < 200) {
                    reasonPhrase2 = "Informational";
                } else if (code2 < 300) {
                    reasonPhrase2 = "Successful";
                } else if (code2 < 400) {
                    reasonPhrase2 = "Redirection";
                } else if (code2 < 500) {
                    reasonPhrase2 = "Client Error";
                } else if (code2 < 600) {
                    reasonPhrase2 = "Server Error";
                } else {
                    reasonPhrase2 = "Unknown Status";
                }
                return new HttpResponseStatus(code2, reasonPhrase2 + " (" + code2 + ')');
        }
    }

    public HttpResponseStatus(int code2, String reasonPhrase2) {
        if (code2 < 0) {
            throw new IllegalArgumentException("code: " + code2 + " (expected: 0+)");
        } else if (reasonPhrase2 == null) {
            throw new NullPointerException("reasonPhrase");
        } else {
            int i = 0;
            while (i < reasonPhrase2.length()) {
                switch (reasonPhrase2.charAt(i)) {
                    case 10:
                    case 13:
                        throw new IllegalArgumentException("reasonPhrase contains one of the following prohibited characters: \\r\\n: " + reasonPhrase2);
                    default:
                        i++;
                }
            }
            this.code = code2;
            this.reasonPhrase = reasonPhrase2;
        }
    }

    public int getCode() {
        return this.code;
    }

    public String getReasonPhrase() {
        return this.reasonPhrase;
    }

    public int hashCode() {
        return getCode();
    }

    public boolean equals(Object o) {
        if ((o instanceof HttpResponseStatus) && getCode() == ((HttpResponseStatus) o).getCode()) {
            return true;
        }
        return false;
    }

    public int compareTo(HttpResponseStatus o) {
        return getCode() - o.getCode();
    }

    public String toString() {
        StringBuilder buf = new StringBuilder(this.reasonPhrase.length() + 5);
        buf.append(this.code);
        buf.append(' ');
        buf.append(this.reasonPhrase);
        return buf.toString();
    }
}