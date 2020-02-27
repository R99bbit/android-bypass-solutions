package com.nostra13.universalimageloader.core.download;

import com.kakao.auth.helper.ServerProtocol;
import com.kakao.util.helper.CommonProtocol;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;

public interface ImageDownloader {

    public enum Scheme {
        HTTP("http"),
        HTTPS(CommonProtocol.URL_SCHEME),
        FILE("file"),
        CONTENT(ServerProtocol.CONTENT_KEY),
        ASSETS("assets"),
        DRAWABLE("drawable"),
        UNKNOWN("");
        
        private String scheme;
        private String uriPrefix;

        private Scheme(String scheme2) {
            this.scheme = scheme2;
            this.uriPrefix = scheme2 + "://";
        }

        public static Scheme ofUri(String uri) {
            Scheme[] arr$;
            if (uri != null) {
                for (Scheme s : values()) {
                    if (s.belongsTo(uri)) {
                        return s;
                    }
                }
            }
            return UNKNOWN;
        }

        private boolean belongsTo(String uri) {
            return uri.toLowerCase(Locale.US).startsWith(this.uriPrefix);
        }

        public String wrap(String path) {
            return this.uriPrefix + path;
        }

        public String crop(String uri) {
            if (belongsTo(uri)) {
                return uri.substring(this.uriPrefix.length());
            }
            throw new IllegalArgumentException(String.format("URI [%1$s] doesn't have expected scheme [%2$s]", new Object[]{uri, this.scheme}));
        }
    }

    InputStream getStream(String str, Object obj) throws IOException;
}