package org.acra.collector;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import java.util.Map;
import java.util.TreeMap;
import org.acra.ACRA;

final class SharedPreferencesCollector {
    SharedPreferencesCollector() {
    }

    public static String collect(Context context) {
        StringBuilder sb = new StringBuilder();
        TreeMap treeMap = new TreeMap();
        treeMap.put(KakaoTalkLinkProtocol.VALIDATION_DEFAULT, PreferenceManager.getDefaultSharedPreferences(context));
        String[] additionalSharedPreferences = ACRA.getConfig().additionalSharedPreferences();
        if (additionalSharedPreferences != null) {
            for (String str : additionalSharedPreferences) {
                treeMap.put(str, context.getSharedPreferences(str, 0));
            }
        }
        for (String str2 : treeMap.keySet()) {
            SharedPreferences sharedPreferences = (SharedPreferences) treeMap.get(str2);
            if (sharedPreferences != null) {
                Map<String, ?> all = sharedPreferences.getAll();
                if (all == null || all.size() <= 0) {
                    sb.append(str2);
                    sb.append('=');
                    sb.append("empty\n");
                } else {
                    for (String next : all.keySet()) {
                        if (!filteredKey(next)) {
                            if (all.get(next) != null) {
                                sb.append(str2);
                                sb.append('.');
                                sb.append(next);
                                sb.append('=');
                                sb.append(all.get(next).toString());
                                sb.append("\n");
                            } else {
                                sb.append(str2);
                                sb.append('.');
                                sb.append(next);
                                sb.append('=');
                                sb.append("null\n");
                            }
                        }
                    }
                }
            } else {
                sb.append("null\n");
            }
            sb.append(10);
        }
        return sb.toString();
    }

    private static boolean filteredKey(String str) {
        for (String matches : ACRA.getConfig().excludeMatchingSharedPreferencesKeys()) {
            if (str.matches(matches)) {
                return true;
            }
        }
        return false;
    }
}