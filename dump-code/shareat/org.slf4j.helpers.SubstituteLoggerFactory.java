package org.slf4j.helpers;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;

public class SubstituteLoggerFactory implements ILoggerFactory {
    final List loggerNameList = new ArrayList();

    public Logger getLogger(String name) {
        synchronized (this.loggerNameList) {
            this.loggerNameList.add(name);
        }
        return NOPLogger.NOP_LOGGER;
    }

    public List getLoggerNameList() {
        List copy = new ArrayList();
        synchronized (this.loggerNameList) {
            try {
                copy.addAll(this.loggerNameList);
            }
        }
        return copy;
    }
}