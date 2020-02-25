package org.acra;

final class CrashReportFileNameParser {
    CrashReportFileNameParser() {
    }

    public boolean isSilent(String str) {
        return str.contains(ACRAConstants.SILENT_SUFFIX);
    }

    public boolean isApproved(String str) {
        return isSilent(str) || str.contains("-approved");
    }
}