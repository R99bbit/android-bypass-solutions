package com.igaworks.model;

import java.util.Comparator;

public class DuplicationConversionKeyComparator implements Comparator<DuplicationConversionKeyModel> {
    public int compare(DuplicationConversionKeyModel lhs, DuplicationConversionKeyModel rhs) {
        long prior1 = lhs.getCompleteTime();
        long prior2 = rhs.getCompleteTime();
        if (prior1 < prior2) {
            return 1;
        }
        if (prior1 == prior2) {
            return 0;
        }
        return -1;
    }
}