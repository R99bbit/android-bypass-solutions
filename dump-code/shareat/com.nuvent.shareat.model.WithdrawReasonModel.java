package com.nuvent.shareat.model;

public class WithdrawReasonModel {
    private boolean isChecked;
    private String name;

    public String getName() {
        return this.name;
    }

    public void setName(String name2) {
        this.name = name2;
    }

    public boolean isChecked() {
        return this.isChecked;
    }

    public void setChecked(boolean isChecked2) {
        this.isChecked = isChecked2;
    }
}