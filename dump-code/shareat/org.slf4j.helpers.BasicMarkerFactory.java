package org.slf4j.helpers;

import java.util.HashMap;
import java.util.Map;
import org.slf4j.IMarkerFactory;
import org.slf4j.Marker;

public class BasicMarkerFactory implements IMarkerFactory {
    Map markerMap = new HashMap();

    public synchronized Marker getMarker(String name) {
        Marker marker;
        if (name == null) {
            throw new IllegalArgumentException("Marker name cannot be null");
        }
        marker = (Marker) this.markerMap.get(name);
        if (marker == null) {
            marker = new BasicMarker(name);
            this.markerMap.put(name, marker);
        }
        return marker;
    }

    public synchronized boolean exists(String name) {
        boolean containsKey;
        if (name == null) {
            containsKey = false;
        } else {
            containsKey = this.markerMap.containsKey(name);
        }
        return containsKey;
    }

    public boolean detachMarker(String name) {
        if (name == null || this.markerMap.remove(name) == null) {
            return false;
        }
        return true;
    }

    public Marker getDetachedMarker(String name) {
        return new BasicMarker(name);
    }
}