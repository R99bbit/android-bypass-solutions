package com.nuvent.shareat.event;

import com.nuvent.shareat.model.friend.FriendModel;

public class FriendStatusEvent {
    private FriendModel model;
    private int requestType;

    public FriendStatusEvent(int requestType2, FriendModel model2) {
        this.model = model2;
        this.requestType = requestType2;
    }

    public int getRequestType() {
        return this.requestType;
    }

    public FriendModel getModel() {
        return this.model;
    }

    public void setModel(FriendModel model2) {
        this.model = model2;
    }
}