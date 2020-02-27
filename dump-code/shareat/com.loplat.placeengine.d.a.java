package com.loplat.placeengine.d;

import java.util.List;

/* compiled from: WifiConstants */
public class a {
    public static float a(float energy) {
        if (energy > 150.0f) {
            return 0.45f;
        }
        if (energy > 50.0f) {
            return 0.3f + ((0.14999998f * (energy - 50.0f)) / 100.0f);
        }
        if (energy > 20.0f) {
            return 0.2f + ((0.10000001f * (energy - 20.0f)) / 30.0f);
        }
        return 0.2f;
    }

    public static float a(List<d> scan) {
        float energy = 0.0f;
        for (d wifi : scan) {
            if (wifi.c > -91) {
                energy += (float) ((wifi.c + 91) * (wifi.c + 91));
            }
        }
        if (energy > 0.0f) {
            return (float) Math.sqrt((double) energy);
        }
        return energy;
    }
}