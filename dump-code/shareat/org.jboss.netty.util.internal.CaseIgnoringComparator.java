package org.jboss.netty.util.internal;

import java.io.Serializable;
import java.util.Comparator;

public final class CaseIgnoringComparator implements Comparator<String>, Serializable {
    public static final CaseIgnoringComparator INSTANCE = new CaseIgnoringComparator();
    private static final long serialVersionUID = 4582133183775373862L;

    private CaseIgnoringComparator() {
    }

    public int compare(String o1, String o2) {
        return o1.compareToIgnoreCase(o2);
    }

    private Object readResolve() {
        return INSTANCE;
    }
}