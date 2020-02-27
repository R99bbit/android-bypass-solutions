package com.nuvent.shareat.model;

import java.io.Serializable;

public class LibInfoModel extends JsonConvertable implements Serializable {
    public int id;
    public String img_path;
    public String img_real;
    public String img_save;
    public String img_sno;
    public String path;

    public Boolean isNetWorkUrl() {
        if (this.id == -1) {
            return Boolean.valueOf(true);
        }
        return Boolean.valueOf(false);
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("LibInfo [path=");
        builder.append(this.path);
        builder.append(", id=");
        builder.append(this.id);
        builder.append("]");
        return builder.toString();
    }
}