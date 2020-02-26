package org.acra.collector;

public class ThreadCollector {
    public static String collect(Thread thread) {
        StringBuilder sb = new StringBuilder();
        if (thread != null) {
            sb.append("id=");
            sb.append(thread.getId());
            sb.append("\n");
            sb.append("name=");
            sb.append(thread.getName());
            sb.append("\n");
            sb.append("priority=");
            sb.append(thread.getPriority());
            sb.append("\n");
            if (thread.getThreadGroup() != null) {
                sb.append("groupName=");
                sb.append(thread.getThreadGroup().getName());
                sb.append("\n");
            }
        } else {
            sb.append("No broken thread, this might be a silent exception.");
        }
        return sb.toString();
    }
}