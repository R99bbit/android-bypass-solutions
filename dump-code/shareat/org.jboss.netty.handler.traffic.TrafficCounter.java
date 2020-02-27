package org.jboss.netty.handler.traffic;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.jboss.netty.util.Timeout;
import org.jboss.netty.util.Timer;
import org.jboss.netty.util.TimerTask;

public class TrafficCounter {
    final AtomicLong checkInterval = new AtomicLong(1000);
    private final AtomicLong cumulativeReadBytes = new AtomicLong();
    private final AtomicLong cumulativeWrittenBytes = new AtomicLong();
    private final AtomicLong currentReadBytes = new AtomicLong();
    private final AtomicLong currentWrittenBytes = new AtomicLong();
    private long lastCumulativeTime;
    private long lastReadBytes;
    private long lastReadThroughput;
    private final AtomicLong lastTime = new AtomicLong();
    private long lastWriteThroughput;
    private long lastWrittenBytes;
    final AtomicBoolean monitorActive = new AtomicBoolean();
    final String name;
    private volatile Timeout timeout;
    /* access modifiers changed from: private */
    public final Timer timer;
    private TimerTask timerTask;
    private final AbstractTrafficShapingHandler trafficShapingHandler;

    private static class TrafficMonitoringTask implements TimerTask {
        private final TrafficCounter counter;
        private final AbstractTrafficShapingHandler trafficShapingHandler1;

        protected TrafficMonitoringTask(AbstractTrafficShapingHandler trafficShapingHandler, TrafficCounter counter2) {
            this.trafficShapingHandler1 = trafficShapingHandler;
            this.counter = counter2;
        }

        public void run(Timeout timeout) throws Exception {
            if (this.counter.monitorActive.get()) {
                this.counter.resetAccounting(System.currentTimeMillis());
                if (this.trafficShapingHandler1 != null) {
                    this.trafficShapingHandler1.doAccounting(this.counter);
                }
                this.counter.timer.newTimeout(this, this.counter.checkInterval.get(), TimeUnit.MILLISECONDS);
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:15:?, code lost:
        return;
     */
    public void start() {
        synchronized (this.lastTime) {
            if (!this.monitorActive.get()) {
                this.lastTime.set(System.currentTimeMillis());
                if (this.checkInterval.get() > 0) {
                    this.monitorActive.set(true);
                    this.timerTask = new TrafficMonitoringTask(this.trafficShapingHandler, this);
                    this.timeout = this.timer.newTimeout(this.timerTask, this.checkInterval.get(), TimeUnit.MILLISECONDS);
                }
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:18:?, code lost:
        return;
     */
    public void stop() {
        synchronized (this.lastTime) {
            if (this.monitorActive.get()) {
                this.monitorActive.set(false);
                resetAccounting(System.currentTimeMillis());
                if (this.trafficShapingHandler != null) {
                    this.trafficShapingHandler.doAccounting(this);
                }
                if (this.timeout != null) {
                    this.timeout.cancel();
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void resetAccounting(long newLastTime) {
        synchronized (this.lastTime) {
            long interval = newLastTime - this.lastTime.getAndSet(newLastTime);
            if (interval != 0) {
                this.lastReadBytes = this.currentReadBytes.getAndSet(0);
                this.lastWrittenBytes = this.currentWrittenBytes.getAndSet(0);
                this.lastReadThroughput = (this.lastReadBytes / interval) * 1000;
                this.lastWriteThroughput = (this.lastWrittenBytes / interval) * 1000;
            }
        }
    }

    public TrafficCounter(AbstractTrafficShapingHandler trafficShapingHandler2, Timer timer2, String name2, long checkInterval2) {
        this.trafficShapingHandler = trafficShapingHandler2;
        this.timer = timer2;
        this.name = name2;
        this.lastCumulativeTime = System.currentTimeMillis();
        configure(checkInterval2);
    }

    public void configure(long newcheckInterval) {
        long newInterval = (newcheckInterval / 10) * 10;
        if (this.checkInterval.get() != newInterval) {
            this.checkInterval.set(newInterval);
            if (newInterval <= 0) {
                stop();
                this.lastTime.set(System.currentTimeMillis());
                return;
            }
            start();
        }
    }

    /* access modifiers changed from: 0000 */
    public void bytesRecvFlowControl(long recv) {
        this.currentReadBytes.addAndGet(recv);
        this.cumulativeReadBytes.addAndGet(recv);
    }

    /* access modifiers changed from: 0000 */
    public void bytesWriteFlowControl(long write) {
        this.currentWrittenBytes.addAndGet(write);
        this.cumulativeWrittenBytes.addAndGet(write);
    }

    public long getCheckInterval() {
        return this.checkInterval.get();
    }

    public long getLastReadThroughput() {
        return this.lastReadThroughput;
    }

    public long getLastWriteThroughput() {
        return this.lastWriteThroughput;
    }

    public long getLastReadBytes() {
        return this.lastReadBytes;
    }

    public long getLastWrittenBytes() {
        return this.lastWrittenBytes;
    }

    public long getCurrentReadBytes() {
        return this.currentReadBytes.get();
    }

    public long getCurrentWrittenBytes() {
        return this.currentWrittenBytes.get();
    }

    public long getLastTime() {
        return this.lastTime.get();
    }

    public long getCumulativeWrittenBytes() {
        return this.cumulativeWrittenBytes.get();
    }

    public long getCumulativeReadBytes() {
        return this.cumulativeReadBytes.get();
    }

    public long getLastCumulativeTime() {
        return this.lastCumulativeTime;
    }

    public void resetCumulativeTime() {
        this.lastCumulativeTime = System.currentTimeMillis();
        this.cumulativeReadBytes.set(0);
        this.cumulativeWrittenBytes.set(0);
    }

    public String getName() {
        return this.name;
    }

    public String toString() {
        return "Monitor " + this.name + " Current Speed Read: " + (this.lastReadThroughput >> 10) + " KB/s, Write: " + (this.lastWriteThroughput >> 10) + " KB/s Current Read: " + (this.currentReadBytes.get() >> 10) + " KB Current Write: " + (this.currentWrittenBytes.get() >> 10) + " KB";
    }
}