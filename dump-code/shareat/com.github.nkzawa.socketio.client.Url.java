package com.github.nkzawa.socketio.client;

import com.kakao.util.helper.CommonProtocol;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.regex.Pattern;

public class Url {
    private static Pattern PATTERN_HTTP = Pattern.compile("^http|ws$");
    private static Pattern PATTERN_HTTPS = Pattern.compile("^(http|ws)s$");

    private Url() {
    }

    public static URL parse(String uri) throws URISyntaxException {
        return parse(new URI(uri));
    }

    public static URL parse(URI uri) {
        String str;
        String str2;
        String str3;
        String str4;
        String protocol = uri.getScheme();
        if (protocol == null || !protocol.matches("^https?|wss?$")) {
            protocol = CommonProtocol.URL_SCHEME;
        }
        int port = uri.getPort();
        if (port == -1) {
            if (PATTERN_HTTP.matcher(protocol).matches()) {
                port = 80;
            } else if (PATTERN_HTTPS.matcher(protocol).matches()) {
                port = 443;
            }
        }
        String path = uri.getRawPath();
        if (path == null || path.length() == 0) {
            path = "/";
        }
        String userInfo = uri.getRawUserInfo();
        String query = uri.getRawQuery();
        String fragment = uri.getRawFragment();
        try {
            StringBuilder append = new StringBuilder().append(protocol).append("://");
            if (userInfo != null) {
                str = userInfo + "@";
            } else {
                str = "";
            }
            StringBuilder append2 = append.append(str).append(uri.getHost());
            if (port != -1) {
                str2 = ":" + port;
            } else {
                str2 = "";
            }
            StringBuilder append3 = append2.append(str2).append(path);
            if (query != null) {
                str3 = "?" + query;
            } else {
                str3 = "";
            }
            StringBuilder append4 = append3.append(str3);
            if (fragment != null) {
                str4 = "#" + fragment;
            } else {
                str4 = "";
            }
            return new URL(append4.append(str4).toString());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public static String extractId(String url) throws MalformedURLException {
        return extractId(new URL(url));
    }

    public static String extractId(URL url) {
        String protocol = url.getProtocol();
        int port = url.getPort();
        if (port == -1) {
            if (PATTERN_HTTP.matcher(protocol).matches()) {
                port = 80;
            } else if (PATTERN_HTTPS.matcher(protocol).matches()) {
                port = 443;
            }
        }
        return protocol + "://" + url.getHost() + ":" + port;
    }
}