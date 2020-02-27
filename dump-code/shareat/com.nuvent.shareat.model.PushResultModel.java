package com.nuvent.shareat.model;

import android.graphics.Bitmap;
import android.net.Uri;
import com.nuvent.shareat.R;
import java.util.ArrayList;

public class PushResultModel {
    public static final int NEW_REVIEW = 2;
    public static final int PARTNER_SNO = 99;
    public static final int PAY_RESULT = 1;
    public static final int PROMOTION = 5;
    public static final int QNA_RESULT = 4;
    public static final int REVIEW_LIKE = 3;
    public Bitmap PromotionBitmap;
    public String board_id;
    public String body;
    public String customScheme;
    public int defaultIconId = R.drawable.shareat;
    public String feed_sno;
    public String img_url;
    public String link_type;
    public String link_url;
    public String message;
    public String partner_sno;
    public String push_sno;
    public String title;
    public Bitmap titleBitmap;
    public String title_img_url;
    public int type = 1;

    public String getPush_sno() {
        return this.push_sno;
    }

    public void setPush_sno(String push_sno2) {
        this.push_sno = push_sno2;
    }

    public void setType(int type2) {
        this.type = type2;
    }

    public void setDefaultIcon(int id) {
        this.defaultIconId = id;
    }

    public int getDefaultIcon() {
        if (this.defaultIconId <= 0) {
            this.defaultIconId = R.drawable.shareat;
        }
        return this.defaultIconId;
    }

    public String getTitle() {
        if (this.title != null || !"".equals(this.title)) {
            return Uri.decode(this.title);
        }
        return "";
    }

    public String getBody() {
        if (this.body != null || !"".equals(this.body)) {
            return Uri.decode(this.body);
        }
        return "";
    }

    public ArrayList<String> getmessageArr() {
        ArrayList<String> msgLists = new ArrayList<>();
        String decode = Uri.decode(this.message);
        if (decode != null && !"".equals(decode)) {
            if (decode.length() > 27) {
                int line = (decode.length() / 27) + 1;
                for (int i = 0; i < line; i++) {
                    int start = i * 27;
                    int end = (i + 1) * 27;
                    if (start + end > decode.length()) {
                        end = decode.length();
                    }
                    String tmp = decode.substring(start, end);
                    msgLists.add(tmp);
                    System.out.println(tmp + "   " + line);
                }
            } else {
                msgLists.add(decode);
            }
        }
        return msgLists;
    }

    public String getmessage() {
        if (this.message != null || !"".equals(this.message)) {
            return Uri.decode(this.message);
        }
        return "";
    }

    public Boolean NuRightDefaultIcon() {
        switch (this.type) {
            case 1:
            case 2:
            case 3:
                return Boolean.valueOf(true);
            case 4:
            case 5:
                return Boolean.valueOf(false);
            default:
                return Boolean.valueOf(false);
        }
    }

    public Boolean isPromotion() {
        if (this.type == 5) {
            return Boolean.valueOf(true);
        }
        return Boolean.valueOf(false);
    }

    public String getCustomScheme() {
        return this.customScheme;
    }

    public void setCustomScheme(String customScheme2) {
        this.customScheme = customScheme2;
    }
}