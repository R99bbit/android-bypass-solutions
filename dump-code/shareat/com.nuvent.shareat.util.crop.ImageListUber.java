package com.nuvent.shareat.util.crop;

import android.net.Uri;
import com.nuvent.shareat.util.crop.camera.Util;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.PriorityQueue;

public class ImageListUber implements IImageList {
    private static final String TAG = "ImageListUber";
    private int mLastListIndex;
    private final PriorityQueue<MergeSlot> mQueue;
    private int[] mSkipCounts;
    private long[] mSkipList;
    private int mSkipListSize;
    private final IImageList[] mSubList;

    private static class AscendingComparator implements Comparator<MergeSlot> {
        private AscendingComparator() {
        }

        public int compare(MergeSlot m1, MergeSlot m2) {
            if (m1.mDateTaken != m2.mDateTaken) {
                return m1.mDateTaken < m2.mDateTaken ? -1 : 1;
            }
            return m1.mListIndex - m2.mListIndex;
        }
    }

    private static class DescendingComparator implements Comparator<MergeSlot> {
        private DescendingComparator() {
        }

        public int compare(MergeSlot m1, MergeSlot m2) {
            if (m1.mDateTaken != m2.mDateTaken) {
                return m1.mDateTaken < m2.mDateTaken ? 1 : -1;
            }
            return m1.mListIndex - m2.mListIndex;
        }
    }

    private static class MergeSlot {
        long mDateTaken;
        IImage mImage;
        private final IImageList mList;
        int mListIndex;
        private int mOffset = -1;

        public MergeSlot(IImageList list, int index) {
            this.mList = list;
            this.mListIndex = index;
        }

        public boolean next() {
            if (this.mOffset >= this.mList.getCount() - 1) {
                return false;
            }
            IImageList iImageList = this.mList;
            int i = this.mOffset + 1;
            this.mOffset = i;
            this.mImage = iImageList.getImageAt(i);
            this.mDateTaken = this.mImage.getDateTaken();
            return true;
        }
    }

    public ImageListUber(IImageList[] sublist, int sort) {
        Comparator descendingComparator;
        this.mSubList = (IImageList[]) sublist.clone();
        if (sort == 1) {
            descendingComparator = new AscendingComparator();
        } else {
            descendingComparator = new DescendingComparator();
        }
        this.mQueue = new PriorityQueue<>(4, descendingComparator);
        this.mSkipList = new long[16];
        this.mSkipListSize = 0;
        this.mSkipCounts = new int[this.mSubList.length];
        this.mLastListIndex = -1;
        this.mQueue.clear();
        int n = this.mSubList.length;
        for (int i = 0; i < n; i++) {
            MergeSlot slot = new MergeSlot(this.mSubList[i], i);
            if (slot.next()) {
                this.mQueue.add(slot);
            }
        }
    }

    public HashMap<String, String> getBucketIds() {
        HashMap<String, String> hashMap = new HashMap<>();
        for (IImageList list : this.mSubList) {
            hashMap.putAll(list.getBucketIds());
        }
        return hashMap;
    }

    public int getCount() {
        int count = 0;
        for (IImageList subList : this.mSubList) {
            count += subList.getCount();
        }
        return count;
    }

    public boolean isEmpty() {
        for (IImageList subList : this.mSubList) {
            if (!subList.isEmpty()) {
                return false;
            }
        }
        return true;
    }

    public IImage getImageAt(int index) {
        if (index < 0 || index > getCount()) {
            throw new IndexOutOfBoundsException("index " + index + " out of range max is " + getCount());
        }
        Arrays.fill(this.mSkipCounts, 0);
        int skipCount = 0;
        int n = this.mSkipListSize;
        for (int i = 0; i < n; i++) {
            long v = this.mSkipList[i];
            int offset = (int) (-1 & v);
            int which = (int) (v >> 32);
            if (skipCount + offset > index) {
                return this.mSubList[which].getImageAt(this.mSkipCounts[which] + (index - skipCount));
            }
            skipCount += offset;
            int[] iArr = this.mSkipCounts;
            iArr[which] = iArr[which] + offset;
        }
        while (true) {
            MergeSlot slot = nextMergeSlot();
            if (slot == null) {
                return null;
            }
            if (skipCount == index) {
                IImage iImage = slot.mImage;
                if (!slot.next()) {
                    return iImage;
                }
                this.mQueue.add(slot);
                return iImage;
            }
            if (slot.next()) {
                this.mQueue.add(slot);
            }
            skipCount++;
        }
    }

    private MergeSlot nextMergeSlot() {
        MergeSlot slot = this.mQueue.poll();
        if (slot == null) {
            return null;
        }
        if (slot.mListIndex == this.mLastListIndex) {
            int lastIndex = this.mSkipListSize - 1;
            long[] jArr = this.mSkipList;
            jArr[lastIndex] = jArr[lastIndex] + 1;
            return slot;
        }
        this.mLastListIndex = slot.mListIndex;
        if (this.mSkipList.length == this.mSkipListSize) {
            long[] temp = new long[(this.mSkipListSize * 2)];
            System.arraycopy(this.mSkipList, 0, temp, 0, this.mSkipListSize);
            this.mSkipList = temp;
        }
        long[] jArr2 = this.mSkipList;
        int i = this.mSkipListSize;
        this.mSkipListSize = i + 1;
        jArr2[i] = (((long) this.mLastListIndex) << 32) | 1;
        return slot;
    }

    public IImage getImageForUri(Uri uri) {
        for (IImageList sublist : this.mSubList) {
            IImage image = sublist.getImageForUri(uri);
            if (image != null) {
                return image;
            }
        }
        return null;
    }

    private void modifySkipCountForDeletedImage(int index) {
        int skipCount = 0;
        int i = 0;
        int n = this.mSkipListSize;
        while (i < n) {
            long v = this.mSkipList[i];
            int offset = (int) (-1 & v);
            if (skipCount + offset > index) {
                this.mSkipList[i] = v - 1;
                return;
            } else {
                skipCount += offset;
                i++;
            }
        }
    }

    private boolean removeImage(IImage image, int index) {
        IImageList list = image.getContainer();
        if (list == null || !list.removeImage(image)) {
            return false;
        }
        modifySkipCountForDeletedImage(index);
        return true;
    }

    public boolean removeImage(IImage image) {
        return removeImage(image, getImageIndex(image));
    }

    public boolean removeImageAt(int index) {
        IImage image = getImageAt(index);
        if (image == null) {
            return false;
        }
        return removeImage(image, index);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:24:0x003f, code lost:
        if (r7.next() == false) goto L_0x0046;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x0041, code lost:
        r14.mQueue.add(r7);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x0046, code lost:
        r6 = r6 + 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:27:0x0048, code lost:
        r7 = nextMergeSlot();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:0x004c, code lost:
        if (r7 == null) goto L_0x0034;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x0050, code lost:
        if (r7.mImage != r15) goto L_0x003b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:32:0x0056, code lost:
        if (r7.next() == false) goto L_0x005d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:33:0x0058, code lost:
        r14.mQueue.add(r7);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:34:0x005d, code lost:
        r11 = r6;
     */
    public synchronized int getImageIndex(IImage image) {
        int i = -1;
        synchronized (this) {
            IImageList list = image.getContainer();
            int listIndex = Util.indexOf(this.mSubList, list);
            if (listIndex != -1) {
                int listOffset = list.getImageIndex(image);
                int skipCount = 0;
                int i2 = 0;
                int n = this.mSkipListSize;
                while (true) {
                    if (i2 >= n) {
                        break;
                    }
                    long value = this.mSkipList[i2];
                    int offset = (int) (-1 & value);
                    if (((int) (value >> 32)) == listIndex) {
                        if (listOffset < offset) {
                            i = skipCount + listOffset;
                            break;
                        }
                        listOffset -= offset;
                    }
                    skipCount += offset;
                    i2++;
                }
            } else {
                throw new IllegalArgumentException();
            }
        }
        return i;
    }

    public void close() {
        for (IImageList close : this.mSubList) {
            close.close();
        }
    }
}