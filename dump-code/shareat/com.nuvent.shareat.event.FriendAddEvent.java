package com.nuvent.shareat.event;

public class FriendAddEvent {
    private String followStatus;
    private String targetSno;

    public FriendAddEvent() {
    }

    public FriendAddEvent(String targetSno2, String followStatus2) {
        this.targetSno = targetSno2;
        this.followStatus = followStatus2;
    }

    public String getTargetSno() {
        return this.targetSno;
    }

    public String getFollowStatus() {
        return this.followStatus;
    }
}