package okhttp3;

import java.io.IOException;
import java.net.CookieHandler;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import okhttp3.Cookie.Builder;
import okhttp3.internal.Util;
import okhttp3.internal.platform.Platform;

public final class JavaNetCookieJar implements CookieJar {
    private final CookieHandler cookieHandler;

    public JavaNetCookieJar(CookieHandler cookieHandler2) {
        this.cookieHandler = cookieHandler2;
    }

    public void saveFromResponse(HttpUrl httpUrl, List<Cookie> list) {
        if (this.cookieHandler != null) {
            ArrayList arrayList = new ArrayList();
            for (Cookie cookie : list) {
                arrayList.add(cookie.toString(true));
            }
            try {
                this.cookieHandler.put(httpUrl.uri(), Collections.singletonMap("Set-Cookie", arrayList));
            } catch (IOException e) {
                Platform platform = Platform.get();
                StringBuilder sb = new StringBuilder();
                sb.append("Saving cookies failed for ");
                sb.append(httpUrl.resolve("/..."));
                platform.log(5, sb.toString(), e);
            }
        }
    }

    public List<Cookie> loadForRequest(HttpUrl httpUrl) {
        List<Cookie> list;
        try {
            ArrayList arrayList = null;
            for (Entry next : this.cookieHandler.get(httpUrl.uri(), Collections.emptyMap()).entrySet()) {
                String str = (String) next.getKey();
                if (("Cookie".equalsIgnoreCase(str) || "Cookie2".equalsIgnoreCase(str)) && !((List) next.getValue()).isEmpty()) {
                    for (String str2 : (List) next.getValue()) {
                        if (arrayList == null) {
                            arrayList = new ArrayList();
                        }
                        arrayList.addAll(decodeHeaderAsJavaNetCookies(httpUrl, str2));
                    }
                }
            }
            if (arrayList != null) {
                list = Collections.unmodifiableList(arrayList);
            } else {
                list = Collections.emptyList();
            }
            return list;
        } catch (IOException e) {
            Platform platform = Platform.get();
            StringBuilder sb = new StringBuilder();
            sb.append("Loading cookies failed for ");
            sb.append(httpUrl.resolve("/..."));
            platform.log(5, sb.toString(), e);
            return Collections.emptyList();
        }
    }

    private List<Cookie> decodeHeaderAsJavaNetCookies(HttpUrl httpUrl, String str) {
        ArrayList arrayList = new ArrayList();
        int length = str.length();
        int i = 0;
        while (i < length) {
            int delimiterOffset = Util.delimiterOffset(str, i, length, (String) ";,");
            int delimiterOffset2 = Util.delimiterOffset(str, i, delimiterOffset, '=');
            String trimSubstring = Util.trimSubstring(str, i, delimiterOffset2);
            if (!trimSubstring.startsWith("$")) {
                String trimSubstring2 = delimiterOffset2 < delimiterOffset ? Util.trimSubstring(str, delimiterOffset2 + 1, delimiterOffset) : "";
                if (trimSubstring2.startsWith("\"") && trimSubstring2.endsWith("\"")) {
                    trimSubstring2 = trimSubstring2.substring(1, trimSubstring2.length() - 1);
                }
                arrayList.add(new Builder().name(trimSubstring).value(trimSubstring2).domain(httpUrl.host()).build());
            }
            i = delimiterOffset + 1;
        }
        return arrayList;
    }
}