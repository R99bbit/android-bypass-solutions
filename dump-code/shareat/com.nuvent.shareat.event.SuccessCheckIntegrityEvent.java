package com.nuvent.shareat.event;

public class SuccessCheckIntegrityEvent {
    private String checkCode;

    public SuccessCheckIntegrityEvent(String checkCode2) {
        this.checkCode = checkCode2;
    }

    public String getCode() {
        return this.checkCode;
    }
}