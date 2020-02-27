package com.nuvent.shareat.activity.crop;

import android.os.Bundle;
import com.nuvent.shareat.activity.MainActionBarActivity;
import java.util.ArrayList;
import java.util.Iterator;

public class MonitoredActivity extends MainActionBarActivity {
    private final ArrayList<LifeCycleListener> mListeners = new ArrayList<>();

    public static class LifeCycleAdapter implements LifeCycleListener {
        public void onActivityCreated(MonitoredActivity activity) {
        }

        public void onActivityDestroyed(MonitoredActivity activity) {
        }

        public void onActivityStarted(MonitoredActivity activity) {
        }

        public void onActivityStopped(MonitoredActivity activity) {
        }
    }

    public interface LifeCycleListener {
        void onActivityCreated(MonitoredActivity monitoredActivity);

        void onActivityDestroyed(MonitoredActivity monitoredActivity);

        void onActivityStarted(MonitoredActivity monitoredActivity);

        void onActivityStopped(MonitoredActivity monitoredActivity);
    }

    public boolean onSearchRequested() {
        return false;
    }

    public void addLifeCycleListener(LifeCycleListener listener) {
        if (!this.mListeners.contains(listener)) {
            this.mListeners.add(listener);
        }
    }

    public void removeLifeCycleListener(LifeCycleListener listener) {
        this.mListeners.remove(listener);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Iterator<LifeCycleListener> it = this.mListeners.iterator();
        while (it.hasNext()) {
            it.next().onActivityCreated(this);
        }
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        Iterator<LifeCycleListener> it = this.mListeners.iterator();
        while (it.hasNext()) {
            it.next().onActivityDestroyed(this);
        }
    }

    /* access modifiers changed from: protected */
    public void onStart() {
        super.onStart();
        Iterator<LifeCycleListener> it = this.mListeners.iterator();
        while (it.hasNext()) {
            it.next().onActivityStarted(this);
        }
    }

    /* access modifiers changed from: protected */
    public void onStop() {
        super.onStop();
        Iterator<LifeCycleListener> it = this.mListeners.iterator();
        while (it.hasNext()) {
            it.next().onActivityStopped(this);
        }
    }
}