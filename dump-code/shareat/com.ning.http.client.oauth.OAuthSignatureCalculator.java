package com.ning.http.client.oauth;

import com.ning.http.client.FluentStringsMap;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilderBase;
import com.ning.http.client.SignatureCalculator;
import com.ning.http.util.Base64;
import com.ning.http.util.UTF8Codec;
import com.ning.http.util.UTF8UrlEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Random;

public class OAuthSignatureCalculator implements SignatureCalculator {
    public static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String KEY_OAUTH_CONSUMER_KEY = "oauth_consumer_key";
    private static final String KEY_OAUTH_NONCE = "oauth_nonce";
    private static final String KEY_OAUTH_SIGNATURE = "oauth_signature";
    private static final String KEY_OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
    private static final String KEY_OAUTH_TIMESTAMP = "oauth_timestamp";
    private static final String KEY_OAUTH_TOKEN = "oauth_token";
    private static final String KEY_OAUTH_VERSION = "oauth_version";
    private static final String OAUTH_SIGNATURE_METHOD = "HMAC-SHA1";
    private static final String OAUTH_VERSION_1_0 = "1.0";
    protected final ConsumerKey consumerAuth;
    protected final ThreadSafeHMAC mac;
    protected final byte[] nonceBuffer = new byte[16];
    protected final Random random;
    protected final RequestToken userAuth;

    static final class OAuthParameterSet {
        private final ArrayList<Parameter> allParameters = new ArrayList<>();

        public OAuthParameterSet add(String key, String value) {
            this.allParameters.add(new Parameter(UTF8UrlEncoder.encode(key), UTF8UrlEncoder.encode(value)));
            return this;
        }

        public String sortAndConcat() {
            Parameter[] arr$;
            Parameter[] params = (Parameter[]) this.allParameters.toArray(new Parameter[this.allParameters.size()]);
            Arrays.sort(params);
            StringBuilder encodedParams = new StringBuilder(100);
            for (Parameter param : params) {
                if (encodedParams.length() > 0) {
                    encodedParams.append('&');
                }
                encodedParams.append(param.key()).append('=').append(param.value());
            }
            return encodedParams.toString();
        }
    }

    static final class Parameter implements Comparable<Parameter> {
        private final String key;
        private final String value;

        public Parameter(String key2, String value2) {
            this.key = key2;
            this.value = value2;
        }

        public String key() {
            return this.key;
        }

        public String value() {
            return this.value;
        }

        public int compareTo(Parameter other) {
            int diff = this.key.compareTo(other.key);
            if (diff == 0) {
                return this.value.compareTo(other.value);
            }
            return diff;
        }

        public String toString() {
            return this.key + "=" + this.value;
        }

        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            Parameter parameter = (Parameter) o;
            if (!this.key.equals(parameter.key)) {
                return false;
            }
            if (!this.value.equals(parameter.value)) {
                return false;
            }
            return true;
        }

        public int hashCode() {
            return (this.key.hashCode() * 31) + this.value.hashCode();
        }
    }

    public OAuthSignatureCalculator(ConsumerKey consumerAuth2, RequestToken userAuth2) {
        this.mac = new ThreadSafeHMAC(consumerAuth2, userAuth2);
        this.consumerAuth = consumerAuth2;
        this.userAuth = userAuth2;
        this.random = new Random(((long) System.identityHashCode(this)) + System.currentTimeMillis());
    }

    public void calculateAndAddSignature(String baseURL, Request request, RequestBuilderBase<?> requestBuilder) {
        String method = request.getMethod();
        String nonce = generateNonce();
        long timestamp = System.currentTimeMillis() / 1000;
        requestBuilder.setHeader("Authorization", constructAuthHeader(calculateSignature(method, baseURL, timestamp, nonce, request.getParams(), request.getQueryParams()), nonce, timestamp));
    }

    public String calculateSignature(String method, String baseURL, long oauthTimestamp, String nonce, FluentStringsMap formParams, FluentStringsMap queryParams) {
        StringBuilder signedText = new StringBuilder(100);
        signedText.append(method);
        signedText.append('&');
        if (baseURL.startsWith("http:")) {
            int i = baseURL.indexOf(":80/", 4);
            if (i > 0) {
                baseURL = baseURL.substring(0, i) + baseURL.substring(i + 3);
            }
        } else if (baseURL.startsWith("https:")) {
            int i2 = baseURL.indexOf(":443/", 5);
            if (i2 > 0) {
                baseURL = baseURL.substring(0, i2) + baseURL.substring(i2 + 4);
            }
        }
        signedText.append(UTF8UrlEncoder.encode(baseURL));
        OAuthParameterSet allParameters = new OAuthParameterSet();
        allParameters.add(KEY_OAUTH_CONSUMER_KEY, this.consumerAuth.getKey());
        allParameters.add(KEY_OAUTH_NONCE, nonce);
        allParameters.add(KEY_OAUTH_SIGNATURE_METHOD, OAUTH_SIGNATURE_METHOD);
        allParameters.add(KEY_OAUTH_TIMESTAMP, String.valueOf(oauthTimestamp));
        allParameters.add(KEY_OAUTH_TOKEN, this.userAuth.getKey());
        allParameters.add(KEY_OAUTH_VERSION, OAUTH_VERSION_1_0);
        if (formParams != null) {
            Iterator<Entry<String, List<String>>> it = formParams.iterator();
            while (it.hasNext()) {
                Entry<String, List<String>> entry = it.next();
                String key = entry.getKey();
                for (String value : entry.getValue()) {
                    allParameters.add(key, value);
                }
            }
        }
        if (queryParams != null) {
            Iterator<Entry<String, List<String>>> it2 = queryParams.iterator();
            while (it2.hasNext()) {
                Entry<String, List<String>> entry2 = it2.next();
                String key2 = entry2.getKey();
                for (String value2 : entry2.getValue()) {
                    allParameters.add(key2, value2);
                }
            }
        }
        String encodedParams = allParameters.sortAndConcat();
        signedText.append('&');
        UTF8UrlEncoder.appendEncoded(signedText, encodedParams);
        return Base64.encode(this.mac.digest(UTF8Codec.toUTF8(signedText.toString())));
    }

    public String constructAuthHeader(String signature, String nonce, long oauthTimestamp) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("OAuth ");
        sb.append(KEY_OAUTH_CONSUMER_KEY).append("=\"").append(this.consumerAuth.getKey()).append("\", ");
        sb.append(KEY_OAUTH_TOKEN).append("=\"").append(this.userAuth.getKey()).append("\", ");
        sb.append(KEY_OAUTH_SIGNATURE_METHOD).append("=\"").append(OAUTH_SIGNATURE_METHOD).append("\", ");
        sb.append(KEY_OAUTH_SIGNATURE).append("=\"");
        UTF8UrlEncoder.appendEncoded(sb, signature).append("\", ");
        sb.append(KEY_OAUTH_TIMESTAMP).append("=\"").append(oauthTimestamp).append("\", ");
        sb.append(KEY_OAUTH_NONCE).append("=\"");
        UTF8UrlEncoder.appendEncoded(sb, nonce);
        sb.append("\", ");
        sb.append(KEY_OAUTH_VERSION).append("=\"").append(OAUTH_VERSION_1_0).append("\"");
        return sb.toString();
    }

    private synchronized String generateNonce() {
        this.random.nextBytes(this.nonceBuffer);
        return Base64.encode(this.nonceBuffer);
    }
}