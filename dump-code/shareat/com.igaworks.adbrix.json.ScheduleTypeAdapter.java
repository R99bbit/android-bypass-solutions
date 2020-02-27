package com.igaworks.adbrix.json;

import com.igaworks.adbrix.model.Schedule;
import com.igaworks.gson.TypeAdapter;
import com.igaworks.gson.stream.JsonReader;
import com.igaworks.gson.stream.JsonToken;
import com.igaworks.gson.stream.JsonWriter;
import java.io.IOException;

public class ScheduleTypeAdapter extends TypeAdapter<Schedule> {
    public Schedule read(JsonReader reader) throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
        }
        return null;
    }

    public void write(JsonWriter arg0, Schedule arg1) throws IOException {
    }
}