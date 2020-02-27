package org.slf4j.helpers;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import org.slf4j.Marker;

public class BasicMarker implements Marker {
    private static String CLOSE = " ]";
    private static String OPEN = "[ ";
    private static String SEP = ", ";
    private static final long serialVersionUID = 1803952589649545191L;
    private final String name;
    private List refereceList;

    BasicMarker(String name2) {
        if (name2 == null) {
            throw new IllegalArgumentException("A marker name cannot be null");
        }
        this.name = name2;
    }

    public String getName() {
        return this.name;
    }

    public synchronized void add(Marker reference) {
        if (reference == null) {
            throw new IllegalArgumentException("A null value cannot be added to a Marker as reference.");
        } else if (!contains(reference)) {
            if (!reference.contains((Marker) this)) {
                if (this.refereceList == null) {
                    this.refereceList = new Vector();
                }
                this.refereceList.add(reference);
            }
        }
    }

    public synchronized boolean hasReferences() {
        return this.refereceList != null && this.refereceList.size() > 0;
    }

    public boolean hasChildren() {
        return hasReferences();
    }

    public synchronized Iterator iterator() {
        Iterator it;
        if (this.refereceList != null) {
            it = this.refereceList.iterator();
        } else {
            it = Collections.EMPTY_LIST.iterator();
        }
        return it;
    }

    public synchronized boolean remove(Marker referenceToRemove) {
        boolean z = false;
        synchronized (this) {
            if (this.refereceList != null) {
                int size = this.refereceList.size();
                int i = 0;
                while (true) {
                    if (i >= size) {
                        break;
                    } else if (referenceToRemove.equals((Marker) this.refereceList.get(i))) {
                        this.refereceList.remove(i);
                        z = true;
                        break;
                    } else {
                        i++;
                    }
                }
            }
        }
        return z;
    }

    public boolean contains(Marker other) {
        if (other == null) {
            throw new IllegalArgumentException("Other cannot be null");
        } else if (equals(other)) {
            return true;
        } else {
            if (hasReferences()) {
                for (int i = 0; i < this.refereceList.size(); i++) {
                    if (((Marker) this.refereceList.get(i)).contains(other)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    public boolean contains(String name2) {
        if (name2 == null) {
            throw new IllegalArgumentException("Other cannot be null");
        } else if (this.name.equals(name2)) {
            return true;
        } else {
            if (hasReferences()) {
                for (int i = 0; i < this.refereceList.size(); i++) {
                    if (((Marker) this.refereceList.get(i)).contains(name2)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof Marker)) {
            return false;
        }
        return this.name.equals(((Marker) obj).getName());
    }

    public int hashCode() {
        return this.name.hashCode();
    }

    public String toString() {
        if (!hasReferences()) {
            return getName();
        }
        Iterator it = iterator();
        StringBuffer sb = new StringBuffer(getName());
        sb.append(' ').append(OPEN);
        while (it.hasNext()) {
            sb.append(((Marker) it.next()).getName());
            if (it.hasNext()) {
                sb.append(SEP);
            }
        }
        sb.append(CLOSE);
        return sb.toString();
    }
}