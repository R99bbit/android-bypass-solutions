package com.loplat.placeengine.d;

import com.loplat.placeengine.utils.LoplatLogger;
import java.util.Iterator;
import java.util.List;

/* compiled from: WifiScanAnalysis */
public class b {
    private static float b(List<d> firsts, List<d> seconds) {
        float similarity = 0.0f;
        float sum_first = 0.0f;
        float sum_second = 0.0f;
        float sum_both = 0.0f;
        float sum_a = 0.0f;
        float sum_b = 0.0f;
        for (d first : firsts) {
            if (first.c > -91) {
                float first_level = (float) (first.c + 91);
                sum_first += first_level * first_level;
                Iterator<d> it = seconds.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    d second = it.next();
                    if (first == null || first.a == null) {
                        LoplatLogger.writeLog("~~~~~~~~~~~~~~~~ DEAD1 ~~~~~~~~~: " + first.a + ", " + first.c + ", " + first.a);
                    } else if (second == null || second.a == null) {
                        LoplatLogger.writeLog("~~~~~~~~~~~~~~~~ DEAD2 ~~~~~~~~~: " + second.a + ", " + second.c + ", " + second.a);
                    } else if (first.a.equals(second.a) && first.d / 1000 == second.d / 1000 && second.c > -91) {
                        float second_level = (float) (second.c + 91);
                        sum_both += first_level * second_level;
                        sum_a += first_level * first_level;
                        sum_b += second_level * second_level;
                    }
                }
                LoplatLogger.writeLog("~~~~~~~~~~~~~~~~ DEAD1 ~~~~~~~~~: " + first.a + ", " + first.c + ", " + first.a);
            }
        }
        for (d second2 : seconds) {
            if (second2.c > -91) {
                float second_level2 = (float) (second2.c + 91);
                sum_second += second_level2 * second_level2;
            }
        }
        float denominator = (sum_first + sum_second) - sum_both;
        if (denominator > 0.0f) {
            similarity = sum_both / denominator;
        }
        float similarity2 = 0.0f;
        float denominator2 = (sum_a + sum_b) - sum_both;
        if (denominator2 > 0.0f) {
            similarity2 = sum_both / denominator2;
        }
        if (similarity > 1.0f) {
            LoplatLogger.writeLog("*** similarity: " + similarity + ", " + sum_first + ", " + sum_second + ", " + sum_both);
            LoplatLogger.writeLog("---first---");
            for (d first2 : firsts) {
                LoplatLogger.writeLog("" + first2.a + ", " + first2.b + ", " + first2.c);
            }
            LoplatLogger.writeLog("---second---");
            for (d second3 : seconds) {
                LoplatLogger.writeLog("" + second3.a + ", " + second3.b + ", " + second3.c);
            }
        }
        if (denominator <= 0.0f || denominator2 <= 0.0f) {
            return similarity;
        }
        float denominator22 = (float) (((double) denominator2) * 1.3d);
        return ((denominator / (denominator + denominator22)) * similarity) + ((similarity2 * denominator22) / (denominator + denominator22));
    }

    private static float c(List<d> firsts, List<d> seconds) {
        float similarity = 0.0f;
        float sum_first = 0.0f;
        float sum_second = 0.0f;
        float sum_both = 0.0f;
        float sum_a = 0.0f;
        float sum_b = 0.0f;
        for (d first : firsts) {
            if (first.c > -91) {
                float first_level = (float) (first.c + 91);
                sum_first += first_level * first_level;
                Iterator<d> it = seconds.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    d second = it.next();
                    if (first == null || first.a == null) {
                        LoplatLogger.writeLog("~~~~~~~~~~~~~~~~ DEAD1 ~~~~~~~~~: " + first.a + ", " + first.c + ", " + first.a);
                    } else if (second == null || second.a == null) {
                        LoplatLogger.writeLog("~~~~~~~~~~~~~~~~ DEAD2 ~~~~~~~~~: " + second.a + ", " + second.c + ", " + second.a);
                    } else if (first.a.equals(second.a) && first.d == second.d && second.c > -91) {
                        float second_level = (float) (second.c + 91);
                        sum_both += first_level * second_level;
                        sum_a += first_level * first_level;
                        sum_b += second_level * second_level;
                    }
                }
                LoplatLogger.writeLog("~~~~~~~~~~~~~~~~ DEAD1 ~~~~~~~~~: " + first.a + ", " + first.c + ", " + first.a);
            }
        }
        for (d second2 : seconds) {
            if (second2.c > -91) {
                float second_level2 = (float) (second2.c + 91);
                sum_second += second_level2 * second_level2;
            }
        }
        float denominator = (float) (Math.sqrt((double) sum_first) * Math.sqrt((double) sum_second));
        if (denominator != 0.0f) {
            similarity = sum_both / denominator;
        }
        float denominator2 = (float) (Math.sqrt((double) sum_a) * Math.sqrt((double) sum_b));
        if (denominator2 != 0.0f) {
            float similarity2 = sum_both / denominator2;
        }
        return similarity;
    }

    public static float a(List<d> firsts, List<d> seconds) {
        float similarity = 0.0f;
        if (seconds != null && seconds.size() > 0) {
            similarity = 0.0f + (b(firsts, seconds) * 0.3f) + (c(firsts, seconds) * 0.7f);
        }
        LoplatLogger.writeLog("similarity: " + similarity);
        return similarity;
    }
}