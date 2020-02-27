package com.nuvent.shareat.event;

import android.os.Bundle;

public class SchemeMainlistEvent {
    private Bundle mParameter;

    public SchemeMainlistEvent(Bundle params) {
        this.mParameter = params;
    }

    public Bundle getParams() {
        return this.mParameter;
    }
}