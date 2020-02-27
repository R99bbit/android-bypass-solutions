package org.jboss.netty.util.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.jboss.netty.util.DebugUtil;

public final class StackTraceSimplifier {
    private static final Pattern EXCLUDED_STACK_TRACE = Pattern.compile("^org\\.jboss\\.netty\\.(util\\.(ThreadRenamingRunnable|internal\\.DeadLockProofWorker)|channel\\.(SimpleChannel(Upstream|Downstream)?Handler|(Default|Static)ChannelPipeline.*))(\\$.*)?$");
    private static final boolean SIMPLIFY_STACK_TRACE = (!DebugUtil.isDebugEnabled());

    public static void simplify(Throwable e) {
        if (SIMPLIFY_STACK_TRACE) {
            if (e.getCause() != null) {
                simplify(e.getCause());
            }
            StackTraceElement[] trace = e.getStackTrace();
            if (trace != null && trace.length != 0 && !EXCLUDED_STACK_TRACE.matcher(trace[0].getClassName()).matches()) {
                List<StackTraceElement> simpleTrace = new ArrayList<>(trace.length);
                simpleTrace.add(trace[0]);
                for (int i = 1; i < trace.length; i++) {
                    if (!EXCLUDED_STACK_TRACE.matcher(trace[i].getClassName()).matches()) {
                        simpleTrace.add(trace[i]);
                    }
                }
                e.setStackTrace((StackTraceElement[]) simpleTrace.toArray(new StackTraceElement[simpleTrace.size()]));
            }
        }
    }

    private StackTraceSimplifier() {
    }
}