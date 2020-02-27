package com.nuvent.shareat.event;

import com.nuvent.shareat.model.store.StoreAllImageModel;
import java.util.ArrayList;

public class ImageListEvent {
    private ArrayList<StoreAllImageModel> mModels;

    public ImageListEvent(ArrayList<StoreAllImageModel> models) {
        this.mModels = models;
    }

    public ArrayList<StoreAllImageModel> getModels() {
        return this.mModels;
    }
}