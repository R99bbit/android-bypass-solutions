package org.slf4j.spi;

import org.slf4j.ILoggerFactory;

public interface LoggerFactoryBinder {
    ILoggerFactory getLoggerFactory();

    String getLoggerFactoryClassStr();
}