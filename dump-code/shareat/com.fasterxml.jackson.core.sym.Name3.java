package com.fasterxml.jackson.core.sym;

public final class Name3 extends Name {
    final int mQuad1;
    final int mQuad2;
    final int mQuad3;

    Name3(String str, int i, int i2, int i3, int i4) {
        super(str, i);
        this.mQuad1 = i2;
        this.mQuad2 = i3;
        this.mQuad3 = i4;
    }

    public boolean equals(int i) {
        return false;
    }

    public boolean equals(int i, int i2) {
        return false;
    }

    public boolean equals(int[] iArr, int i) {
        return i == 3 && iArr[0] == this.mQuad1 && iArr[1] == this.mQuad2 && iArr[2] == this.mQuad3;
    }
}