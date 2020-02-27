package com.fasterxml.jackson.core.sym;

public final class Name2 extends Name {
    final int mQuad1;
    final int mQuad2;

    Name2(String str, int i, int i2, int i3) {
        super(str, i);
        this.mQuad1 = i2;
        this.mQuad2 = i3;
    }

    public boolean equals(int i) {
        return false;
    }

    public boolean equals(int i, int i2) {
        return i == this.mQuad1 && i2 == this.mQuad2;
    }

    public boolean equals(int[] iArr, int i) {
        return i == 2 && iArr[0] == this.mQuad1 && iArr[1] == this.mQuad2;
    }
}