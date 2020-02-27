package com.nuvent.shareat.event;

import com.nuvent.shareat.model.store.StoreModel;

public class RefreshQuickPayListEvent {
    private StoreModel mStoreModel = null;

    public RefreshQuickPayListEvent(StoreModel sm) {
        this.mStoreModel = sm;
    }

    public StoreModel getStoreModel() {
        return this.mStoreModel;
    }
}