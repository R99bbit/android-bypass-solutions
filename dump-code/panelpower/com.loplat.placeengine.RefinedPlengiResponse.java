package com.loplat.placeengine;

import com.loplat.placeengine.PlengiResponse.District;
import com.loplat.placeengine.PlengiResponse.Location;
import java.io.Serializable;

public class RefinedPlengiResponse implements Serializable {
    public District district;
    public String errorReason;
    public Location location;
    public int result;

    public RefinedPlengiResponse() {
        this.result = -1;
        this.errorReason = "";
    }

    public PlengiResponse toPlengiResponse() {
        PlengiResponse plengiResponse = new PlengiResponse();
        plengiResponse.result = this.result;
        plengiResponse.errorReason = this.errorReason;
        plengiResponse.district = this.district;
        plengiResponse.location = this.location;
        return plengiResponse;
    }

    public RefinedPlengiResponse(int i, String str, District district2, Location location2) {
        this.result = i;
        this.errorReason = str;
        this.district = district2;
        this.location = location2;
    }
}