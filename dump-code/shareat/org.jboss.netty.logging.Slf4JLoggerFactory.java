package org.jboss.netty.logging;

import org.slf4j.LoggerFactory;

public class Slf4JLoggerFactory extends InternalLoggerFactory {
    public InternalLogger newInstance(String name) {
        return new Slf4JLogger(LoggerFactory.getLogger(name));
    }
}