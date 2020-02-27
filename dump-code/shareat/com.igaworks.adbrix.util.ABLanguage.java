package com.igaworks.adbrix.util;

import android.content.Context;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class ABLanguage {
    private static ABLanguage instance;
    private Map<String, String> lang = new HashMap();

    private ABLanguage(Context context) {
        setMessageByLocale();
    }

    public static ABLanguage getInstance(Context context) {
        if (instance == null) {
            instance = new ABLanguage(context);
        }
        return instance;
    }

    public void setMessageByLocale() {
        Locale defaultLocale = Locale.getDefault();
        String locale = defaultLocale.getLanguage();
        if (locale.contains("ko")) {
            this.lang.put("shareWith", "\uacf5\uc720");
            this.lang.put("close", "\ub2eb\uae30");
            this.lang.put("canNotParticipate", "\uc8c4\uc1a1\ud569\ub2c8\ub2e4.\n\uc7a0\uc2dc \ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574\uc8fc\uc138\uc694.");
        } else if (locale.contains("ja")) {
            this.lang.put("shareWith", "\u30b7\u30a7\u30a2");
            this.lang.put("close", "\u9589\u3058\u308b");
            this.lang.put("canNotParticipate", "Sorry.\nPlease try again later.");
        } else if (locale.contains("zh")) {
            String country = defaultLocale.getCountry().toLowerCase();
            if (country.equals("cn")) {
                this.lang.put("shareWith", "\u5171\u4eab");
                this.lang.put("close", "\u5173\u95ed");
                this.lang.put("canNotParticipate", "Sorry.\nPlease try again later.");
            } else if (country.equals("tw")) {
                this.lang.put("shareWith", "\u5171\u4eab");
                this.lang.put("close", "\u95dc\u9589");
                this.lang.put("canNotParticipate", "Sorry.\nPlease try again later.");
            }
        } else {
            this.lang.put("shareWith", "Share");
            this.lang.put("close", "Close");
            this.lang.put("canNotParticipate", "Sorry.\nPlease try again later.");
        }
    }

    public String getMessageByLocale(String key) {
        if (this.lang.containsKey(key)) {
            return this.lang.get(key);
        }
        return "";
    }
}