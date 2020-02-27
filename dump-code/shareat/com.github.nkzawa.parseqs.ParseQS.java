package com.github.nkzawa.parseqs;

import com.github.nkzawa.global.Global;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

public class ParseQS {
    private ParseQS() {
    }

    public static String encode(Map<String, String> obj) {
        StringBuilder str = new StringBuilder();
        for (Entry<String, String> entry : obj.entrySet()) {
            if (str.length() > 0) {
                str.append("&");
            }
            str.append(Global.encodeURIComponent(entry.getKey())).append("=").append(Global.encodeURIComponent(entry.getValue()));
        }
        return str.toString();
    }

    public static Map<String, String> decode(String qs) {
        Map<String, String> qry = new HashMap<>();
        for (String _pair : qs.split("&")) {
            String[] pair = _pair.split("=");
            qry.put(Global.decodeURIComponent(pair[0]), pair.length > 1 ? Global.decodeURIComponent(pair[1]) : "");
        }
        return qry;
    }
}