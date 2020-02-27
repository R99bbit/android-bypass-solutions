package com.nuvent.shareat.event;

import com.nuvent.shareat.model.friend.FriendModel;
import java.util.ArrayList;

public class AddressStateEvent {
    private ArrayList<FriendModel> models;
    private int state;

    public AddressStateEvent() {
        this.state = 1;
        this.models = new ArrayList<>();
    }

    public AddressStateEvent(int state2, ArrayList<FriendModel> models2) {
        this.models = models2;
        this.state = state2;
    }

    public ArrayList<FriendModel> getModel() {
        return this.models;
    }

    public void setModel(ArrayList<FriendModel> model) {
        this.models = model;
    }

    public int getState() {
        return this.state;
    }

    public void setState(int state2) {
        this.state = state2;
    }
}