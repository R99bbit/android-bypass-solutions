package com.nuvent.shareat.event;

import com.nuvent.shareat.model.store.StoreParamsModel;

public class ExternalStoreListEvent {
    private StoreParamsModel mModel;

    public ExternalStoreListEvent(StoreParamsModel model) {
        this.mModel = model;
    }

    public StoreParamsModel getModel() {
        return this.mModel;
    }
}