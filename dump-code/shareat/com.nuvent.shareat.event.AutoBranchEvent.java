package com.nuvent.shareat.event;

import com.nuvent.shareat.model.store.StoreModel;

public class AutoBranchEvent {
    private StoreModel mStoreModel = null;

    public AutoBranchEvent(StoreModel sm) {
        this.mStoreModel = sm;
    }

    public StoreModel getStoreModel() {
        return this.mStoreModel;
    }
}