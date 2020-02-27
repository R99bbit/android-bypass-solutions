package com.ning.http.multipart;

import java.util.Timer;
import java.util.TimerTask;

public class FilePartStallHandler extends TimerTask {
    private boolean _failed = false;
    private Timer _timer;
    private long _waitTime;
    private boolean _written = false;

    public FilePartStallHandler(long waitTime, FilePart filePart) {
        this._waitTime = waitTime;
    }

    public void completed() {
        if (this._waitTime > 0) {
            this._timer.cancel();
        }
    }

    public boolean isFailed() {
        return this._failed;
    }

    public void run() {
        if (!this._written) {
            this._failed = true;
            this._timer.cancel();
        }
        this._written = false;
    }

    public void start() {
        if (this._waitTime > 0) {
            this._timer = new Timer();
            this._timer.scheduleAtFixedRate(this, this._waitTime, this._waitTime);
        }
    }

    public void writeHappened() {
        this._written = true;
    }
}