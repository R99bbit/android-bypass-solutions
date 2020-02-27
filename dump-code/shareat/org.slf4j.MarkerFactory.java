package org.slf4j;

import org.slf4j.helpers.BasicMarkerFactory;
import org.slf4j.helpers.Util;
import org.slf4j.impl.StaticMarkerBinder;

public class MarkerFactory {
    static IMarkerFactory markerFactory;

    private MarkerFactory() {
    }

    static {
        try {
            markerFactory = StaticMarkerBinder.SINGLETON.getMarkerFactory();
        } catch (NoClassDefFoundError e) {
            markerFactory = new BasicMarkerFactory();
        } catch (Exception e2) {
            Util.report("Unexpected failure while binding MarkerFactory", e2);
        }
    }

    public static Marker getMarker(String name) {
        return markerFactory.getMarker(name);
    }

    public static Marker getDetachedMarker(String name) {
        return markerFactory.getDetachedMarker(name);
    }

    public static IMarkerFactory getIMarkerFactory() {
        return markerFactory;
    }
}