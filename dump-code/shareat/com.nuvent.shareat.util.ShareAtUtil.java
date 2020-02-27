package com.nuvent.shareat.util;

import com.nuvent.shareat.model.SpanTagModel;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Random;

public class ShareAtUtil {
    public static final int SHARE_TEXT_TYPE_KAKAO = 0;
    public static final int SHARE_TEXT_TYPE_SMS = 1;
    public static String[] menuNameArray = {"\ub9c8\ub298\uac04\uc7a5\uce58\ud0a8", "\uba85\ub780\ud30c\uc2a4\ud0c0", "\ub9e4\uc6b4\ub3fc\uc9c0\uac08\ube44\ucc1c", "\ubbf8\uc18c\ub77c\uba58", "\ud574\ubb3c\uc1a5\ubc25"};

    public static String replaceCardNum(String cNo) {
        if (cNo == null || cNo.isEmpty()) {
            return cNo;
        }
        String[] nos = cNo.replace("*", "/").split("/");
        return nos[nos.length - 1];
    }

    public static String getDistanceMark(String distance) {
        String result_int = new DecimalFormat("#,###").format((long) Integer.parseInt(distance));
        int repliceInt = Integer.parseInt(distance);
        if (repliceInt < 1000) {
            return result_int + "m";
        }
        if (repliceInt < 1000) {
            return "";
        }
        return new DecimalFormat("#.#").format((double) (((float) (repliceInt / 100)) / 10.0f)) + "Km";
    }

    public static ArrayList<SpanTagModel> getTags(String contents) {
        ArrayList<SpanTagModel> tagsInstance = new ArrayList<>();
        int length = contents.length();
        SpanTagModel tag = null;
        for (int i = 0; i < length; i++) {
            char c = contents.charAt(i);
            if (c == '#') {
                tag = new SpanTagModel();
                tag.start = i;
            } else if (c == ' ' && tag != null) {
                tag.end = i;
                tagsInstance.add(tag);
                tag = null;
            }
        }
        if (tag != null) {
            tag.end = length;
            tagsInstance.add(tag);
        }
        return tagsInstance;
    }

    public static String getSharedUrl(int type) {
        String shareText = null;
        switch (type) {
            case 0:
                shareText = "[\uc250\uc5b4\uc573]\n\uc5b4\ub514\uc11c \ub9db\uc788\ub294 \ub0c4\uc0c8 \uc548\ub098\uc694? \ubc29\uae08 \ub2f9\uc2e0 \uc8fc\ubcc0\uc5d0\uc11c \ub530\ub048\ub530\ub048\ud55c '%s'\uc774 \ud310\ub9e4\ub418\uc5c8\ub2e4\uad6c\uc694.\n-\n1\ucd08\uc804 \uc5b4\ub5a4 \uba54\ub274\uac00 \ud314\ub9ac\ub294\uc9c0 \ubcf4\uace0, 365\uc77c \uc5b8\uc81c\ub098 \ud560\uc778\ud61c\ud0dd\uc740 \ub364!\n-\n#\ub108\uc88b\uc73c\ub77c\uace0\ub9cc\ub4e0\uc571-\uc250\uc5b4\uc573";
                break;
            case 1:
                shareText = "[\uc250\uc5b4\uc573]\n\uc5b4\ub514\uc11c \ub9db\uc788\ub294 \ub0c4\uc0c8 \uc548\ub098\uc694? \ubc29\uae08 \ub2f9\uc2e0 \uc8fc\ubcc0\uc5d0\uc11c \ub530\ub048\ub530\ub048\ud55c '%s'\uc774 \ud310\ub9e4\ub418\uc5c8\ub2e4\uad6c\uc694.\n#\ub108\uc88b\uc73c\ub77c\uace0\ub9cc\ub4e0\uc571-\uc250\uc5b4\uc573\n" + "http://goo.gl/zOjDvp";
                break;
        }
        return String.format(shareText, new Object[]{menuNameArray[new Random().nextInt(menuNameArray.length - 1)]});
    }
}