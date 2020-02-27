package com.fasterxml.jackson.core.format;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.format.InputAccessor.Std;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

public class DataFormatDetector {
    public static final int DEFAULT_MAX_INPUT_LOOKAHEAD = 64;
    protected final JsonFactory[] _detectors;
    protected final int _maxInputLookahead;
    protected final MatchStrength _minimalMatch;
    protected final MatchStrength _optimalMatch;

    public DataFormatDetector(JsonFactory... jsonFactoryArr) {
        this(jsonFactoryArr, MatchStrength.SOLID_MATCH, MatchStrength.WEAK_MATCH, 64);
    }

    public DataFormatDetector(Collection<JsonFactory> collection) {
        this((JsonFactory[]) collection.toArray(new JsonFactory[collection.size()]));
    }

    public DataFormatDetector withOptimalMatch(MatchStrength matchStrength) {
        return matchStrength == this._optimalMatch ? this : new DataFormatDetector(this._detectors, matchStrength, this._minimalMatch, this._maxInputLookahead);
    }

    public DataFormatDetector withMinimalMatch(MatchStrength matchStrength) {
        return matchStrength == this._minimalMatch ? this : new DataFormatDetector(this._detectors, this._optimalMatch, matchStrength, this._maxInputLookahead);
    }

    public DataFormatDetector withMaxInputLookahead(int i) {
        return i == this._maxInputLookahead ? this : new DataFormatDetector(this._detectors, this._optimalMatch, this._minimalMatch, i);
    }

    private DataFormatDetector(JsonFactory[] jsonFactoryArr, MatchStrength matchStrength, MatchStrength matchStrength2, int i) {
        this._detectors = jsonFactoryArr;
        this._optimalMatch = matchStrength;
        this._minimalMatch = matchStrength2;
        this._maxInputLookahead = i;
    }

    public DataFormatMatcher findFormat(InputStream inputStream) throws IOException {
        return _findFormat(new Std(inputStream, new byte[this._maxInputLookahead]));
    }

    public DataFormatMatcher findFormat(byte[] bArr) throws IOException {
        return _findFormat(new Std(bArr));
    }

    public DataFormatMatcher findFormat(byte[] bArr, int i, int i2) throws IOException {
        return _findFormat(new Std(bArr, i, i2));
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('[');
        int length = this._detectors.length;
        if (length > 0) {
            sb.append(this._detectors[0].getFormatName());
            for (int i = 1; i < length; i++) {
                sb.append(", ");
                sb.append(this._detectors[i].getFormatName());
            }
        }
        sb.append(']');
        return sb.toString();
    }

    private DataFormatMatcher _findFormat(Std std) throws IOException {
        MatchStrength matchStrength;
        JsonFactory jsonFactory;
        JsonFactory jsonFactory2;
        JsonFactory[] jsonFactoryArr = this._detectors;
        int length = jsonFactoryArr.length;
        int i = 0;
        JsonFactory jsonFactory3 = null;
        MatchStrength matchStrength2 = null;
        while (true) {
            if (i >= length) {
                matchStrength = matchStrength2;
                jsonFactory = jsonFactory3;
                break;
            }
            jsonFactory = jsonFactoryArr[i];
            std.reset();
            matchStrength = jsonFactory.hasFormat(std);
            if (matchStrength == null) {
                jsonFactory2 = jsonFactory3;
            } else if (matchStrength.ordinal() < this._minimalMatch.ordinal()) {
                jsonFactory2 = jsonFactory3;
            } else if (jsonFactory3 != null && matchStrength2.ordinal() >= matchStrength.ordinal()) {
                jsonFactory2 = jsonFactory3;
            } else if (matchStrength.ordinal() >= this._optimalMatch.ordinal()) {
                break;
            } else {
                matchStrength2 = matchStrength;
                jsonFactory2 = jsonFactory;
            }
            i++;
            jsonFactory3 = jsonFactory2;
        }
        return std.createMatcher(jsonFactory, matchStrength);
    }
}