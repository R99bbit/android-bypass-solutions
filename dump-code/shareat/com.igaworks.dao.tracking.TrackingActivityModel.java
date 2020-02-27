package com.igaworks.dao.tracking;

public class TrackingActivityModel {
    private int id;
    private int isDirty;
    private String key;
    private String value;

    public TrackingActivityModel(int id2, String key2, String value2) {
        this.id = id2;
        this.key = key2;
        this.value = value2;
        this.isDirty = 0;
    }

    public TrackingActivityModel(String key2, String value2) {
        this.id = -1;
        this.key = key2;
        this.value = value2;
        this.isDirty = 0;
    }

    public TrackingActivityModel(int id2, String key2, String value2, int isDirty2) {
        this.id = id2;
        this.key = key2;
        this.value = value2;
        this.isDirty = isDirty2;
    }

    public int getId() {
        return this.id;
    }

    public String getKey() {
        return this.key;
    }

    public String getValue() {
        return this.value;
    }

    public int getIsDirty() {
        return this.isDirty;
    }
}