package com.nuvent.shareat.event;

public class RequestAutoBranchEvent {
    public int mRequestAutoBranchCommand = 0;

    public class RequestAutoBranchCommand {
        public static final int NONE = 0;
        public static final int SEARCHING = 3;
        public static final int START = 1;
        public static final int STOP = 2;

        public RequestAutoBranchCommand() {
        }
    }

    public RequestAutoBranchEvent(int nRequestAutoBranchCommand) {
        this.mRequestAutoBranchCommand = nRequestAutoBranchCommand;
    }
}