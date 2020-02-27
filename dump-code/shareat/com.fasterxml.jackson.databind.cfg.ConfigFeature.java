package com.fasterxml.jackson.databind.cfg;

public interface ConfigFeature {
    boolean enabledByDefault();

    int getMask();
}