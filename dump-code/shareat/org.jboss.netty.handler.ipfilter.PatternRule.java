package org.jboss.netty.handler.ipfilter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.internal.StringUtil;

public class PatternRule implements IpFilterRule, Comparable<Object> {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(PatternRule.class);
    private Pattern ipPattern;
    private boolean isAllowRule = true;
    private boolean localhost;
    private Pattern namePattern;
    private final String pattern;

    public PatternRule(boolean allow, String pattern2) {
        this.isAllowRule = allow;
        this.pattern = pattern2;
        parse(pattern2);
    }

    public String getPattern() {
        return this.pattern;
    }

    public boolean isAllowRule() {
        return this.isAllowRule;
    }

    public boolean isDenyRule() {
        return !this.isAllowRule;
    }

    public boolean contains(InetAddress inetAddress) {
        if (this.localhost && isLocalhost(inetAddress)) {
            return true;
        }
        if (this.ipPattern != null && this.ipPattern.matcher(inetAddress.getHostAddress()).matches()) {
            return true;
        }
        if (this.namePattern == null || !this.namePattern.matcher(inetAddress.getHostName()).matches()) {
            return false;
        }
        return true;
    }

    private void parse(String pattern2) {
        if (pattern2 != null) {
            String ip = "";
            String name = "";
            for (String c : StringUtil.split(pattern2, ',')) {
                String c2 = c.trim();
                if ("n:localhost".equals(c2)) {
                    this.localhost = true;
                } else if (c2.startsWith("n:")) {
                    name = addRule(name, c2.substring(2));
                } else if (c2.startsWith("i:")) {
                    ip = addRule(ip, c2.substring(2));
                }
            }
            if (ip.length() != 0) {
                this.ipPattern = Pattern.compile(ip);
            }
            if (name.length() != 0) {
                this.namePattern = Pattern.compile(name);
            }
        }
    }

    private static String addRule(String pattern2, String rule) {
        if (rule == null || rule.length() == 0) {
            return pattern2;
        }
        if (pattern2.length() != 0) {
            pattern2 = pattern2 + "|";
        }
        return pattern2 + '(' + rule.replaceAll("\\.", "\\\\.").replaceAll("\\*", ".*").replaceAll("\\?", ".") + ')';
    }

    private static boolean isLocalhost(InetAddress address) {
        try {
            if (address.equals(InetAddress.getLocalHost())) {
                return true;
            }
        } catch (UnknownHostException e) {
            if (logger.isInfoEnabled()) {
                logger.info("error getting ip of localhost", e);
            }
        }
        try {
            for (InetAddress addr : InetAddress.getAllByName("127.0.0.1")) {
                if (addr.equals(address)) {
                    return true;
                }
            }
        } catch (UnknownHostException e2) {
            if (logger.isInfoEnabled()) {
                logger.info("error getting ip of localhost", e2);
            }
        }
        return false;
    }

    public int compareTo(Object o) {
        if (o == null || !(o instanceof PatternRule)) {
            return -1;
        }
        PatternRule p = (PatternRule) o;
        if (p.isAllowRule() && !this.isAllowRule) {
            return -1;
        }
        if (this.pattern == null && p.pattern == null) {
            return 0;
        }
        if (this.pattern != null) {
            return this.pattern.compareTo(p.getPattern());
        }
        return -1;
    }
}