package com.nuvent.shareat.event;

import com.nuvent.shareat.model.store.StoreModel;

public class CardSetStoreEvent {
    private StoreModel mModel;

    public CardSetStoreEvent(StoreModel mModel2) {
        this.mModel = mModel2;
    }

    public StoreModel getmModel() {
        return this.mModel;
    }
}