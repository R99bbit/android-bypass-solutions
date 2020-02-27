package com.nuvent.shareat.model;

import android.content.Context;
import android.content.res.Resources;
import com.nuvent.shareat.R;
import com.nuvent.shareat.api.ApiUrl;
import java.io.Serializable;

public class InstagramModel implements Serializable {
    public String fileName;
    public String msg;
    public String photoBy;
    public String shareat;
    public String urlStr;

    public InstagramModel(String msg2, String photoBy2, String pSno, String fileName2) {
        System.out.println("msg = " + msg2 + "\nphotoBy = " + photoBy2 + "\npSno = " + pSno + "\n");
        this.msg = msg2.trim();
        this.photoBy = photoBy2.trim();
        this.urlStr = String.format(ApiUrl.SHARE_URL, new Object[]{pSno, "instagram"});
        this.fileName = fileName2;
    }

    public String getCaptionText(Context con) {
        Resources resources = con.getResources();
        StringBuilder sb = new StringBuilder();
        sb.append(resources.getString(R.string.instagram_share_account) + "\n...\n");
        sb.append(this.msg + "\n");
        sb.append(String.format("Photo by %1$s", new Object[]{this.photoBy}) + "\n");
        sb.append("URL : " + this.urlStr + "\n");
        sb.append(resources.getString(R.string.instagram_share_msg));
        return sb.toString();
    }

    public String getFileName() {
        return this.fileName;
    }
}