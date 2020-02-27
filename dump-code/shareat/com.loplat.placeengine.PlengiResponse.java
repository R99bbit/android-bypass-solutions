package com.loplat.placeengine;

import java.util.ArrayList;

public class PlengiResponse {
    public int enterType;
    public String errorReason;
    public ArrayList<Person> persons;
    public Place place;
    public int placeEvent;
    public int result;
    public int type;
    public Uuidp uuidp;

    public class EnterType {
        public static final int ENTER = 0;
        public static final int NEARBY = 1;

        public EnterType() {
        }
    }

    public class MonitoringType {
        public static final int STAY = 0;
        public static final int TRACKING = 1;

        public MonitoringType() {
        }
    }

    public static class Person {
        public String uniqueUserId;

        public Person(String uniqueUserId2) {
            this.uniqueUserId = uniqueUserId2;
        }
    }

    public static class Place {
        public float accuracy;
        public String category;
        public String client_code;
        public int floor;
        public double lat;
        public double lat_est;
        public double lng;
        public double lng_est;
        public long loplatid;
        public String name;
        public String tags;
        public float threshold;
    }

    public class PlaceEvent {
        public static final int ENTER = 1;
        public static final int LEAVE = 2;

        public PlaceEvent() {
        }
    }

    public class PlaceStatus {
        public static final int MOVE = 0;
        public static final int STAY = 2;

        public PlaceStatus() {
        }
    }

    public class ResponseType {
        public static final int NEARBY_DEVICE = 5;
        public static final int PLACE = 1;
        public static final int PLACE_EVENT = 2;
        public static final int PLACE_TRACKING = 3;
        public static final int UUIDP = 4;

        public ResponseType() {
        }
    }

    public class Result {
        public static final int ERROR_CLOUD_ACCESS = 2;
        public static final int FAIL_INTERNET_UNAVAILABLE = 3;
        public static final int FAIL_WIFI_SCAN_UNAVAILABLE = 4;
        public static final int SUCCESS = 1;

        public Result() {
        }
    }

    public static class Uuidp {
        public String description;
        public long placeid;
        public float similarity;
        public long visitcount;
    }

    public static class Visit {
        public long enter;
        public long leave;
        public long placeid;
        public int visitid;

        public Visit(int visitid2, long placeid2, long enter2, long leave2) {
            this.visitid = visitid2;
            this.placeid = placeid2;
            this.enter = enter2;
            this.leave = leave2;
        }
    }
}