package com.github.nkzawa.backo;

public class Backoff {
    private int attempts = 0;
    private int factor = 2;
    private double jitter = 0.0d;
    private long max = 10000;
    private long ms = 100;

    public long duration() {
        int i = this.attempts;
        this.attempts = i + 1;
        long ms2 = this.ms * ((long) Math.pow((double) this.factor, (double) i));
        if (this.jitter != 0.0d) {
            double rand = Math.random();
            int deviation = (int) Math.floor(this.jitter * rand * ((double) ms2));
            ms2 = (((int) Math.floor(10.0d * rand)) & 1) == 0 ? ms2 - ((long) deviation) : ms2 + ((long) deviation);
        }
        if (ms2 < this.ms) {
            ms2 = Long.MAX_VALUE;
        }
        return Math.min(ms2, this.max);
    }

    public void reset() {
        this.attempts = 0;
    }

    public Backoff setMin(long min) {
        this.ms = min;
        return this;
    }

    public Backoff setMax(long max2) {
        this.max = max2;
        return this;
    }

    public Backoff setFactor(int factor2) {
        this.factor = factor2;
        return this;
    }

    public Backoff setJitter(double jitter2) {
        this.jitter = jitter2;
        return this;
    }

    public int getAttempts() {
        return this.attempts;
    }
}