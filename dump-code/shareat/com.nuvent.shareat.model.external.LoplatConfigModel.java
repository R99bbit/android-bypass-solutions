package com.nuvent.shareat.model.external;

import java.io.Serializable;

public class LoplatConfigModel implements Serializable {
    private int branchInfoSavePeriod;
    private int duplicateByPassPeriod;
    private int moveScanPeriod;
    private int searchFailPeriod;
    private int stayScanPeriod;

    public int getMoveScanPeriod() {
        return this.moveScanPeriod;
    }

    public void setMoveScanPeriod(int moveScanPeriod2) {
        this.moveScanPeriod = moveScanPeriod2;
    }

    public int getStayScanPeriod() {
        return this.stayScanPeriod;
    }

    public void setStayScanPeriod(int stayScanPeriod2) {
        this.stayScanPeriod = stayScanPeriod2;
    }

    public int getBranchInfoSavePeriod() {
        return this.branchInfoSavePeriod;
    }

    public void setBranchInfoSavePeriod(int branchInfoSavePeriod2) {
        this.branchInfoSavePeriod = branchInfoSavePeriod2;
    }

    public int getSearchFailPeriod() {
        return this.searchFailPeriod;
    }

    public void setSearchFailPeriod(int searchFailPeriod2) {
        this.searchFailPeriod = searchFailPeriod2;
    }

    public int getDuplicateByPassPeriod() {
        return this.duplicateByPassPeriod;
    }

    public void setDuplicateByPassPeriod(int duplicateByPassPeriod2) {
        this.duplicateByPassPeriod = duplicateByPassPeriod2;
    }
}