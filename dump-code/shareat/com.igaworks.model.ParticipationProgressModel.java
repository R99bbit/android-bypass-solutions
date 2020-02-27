package com.igaworks.model;

public class ParticipationProgressModel {
    public int ConversionKey;

    public ParticipationProgressModel() {
    }

    public ParticipationProgressModel(int conversionKey) {
        this.ConversionKey = conversionKey;
    }

    public int getConversionKey() {
        return this.ConversionKey;
    }

    public void setConversionKey(int conversionKey) {
        this.ConversionKey = conversionKey;
    }
}