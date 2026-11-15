package sealing.wax.bridge;

/** Host-side mirror of the Kotlin facade: verifies the JNI bridge end-to-end. */
public class WaxNative {
    static { System.loadLibrary("waxhost"); }

    public static native long createSession(boolean asInviter);
    public static native void freeSession(long h);
    public static native int sessionRole(long h);
    public static native String invite(long h, byte[] secret);
    public static native String reply(long h, String inviteB64, byte[] secret);
    public static native void finish(long h, String replyB64);
    public static native String sas(long h);
    public static native void setPadding(long h, boolean enabled, int thresholdB64);
    public static native long[] counters(long h);
    public static native String[] sealText(long h, byte[] pt);
    public static native byte[] openText(long h, String pieceB64);
    public static native byte[] exportState(long h);
    public static native long importState(byte[] blob, long sendNext, long recvHwm);
    public static native byte[] flipStateRole(byte[] blob);
    public static native long fileSealBegin(long h, byte[] meta, long fileSize);
    public static native int fileChunkRoom(long se);
    public static native byte[] fileSealChunk(long se, byte[] data);
    public static native boolean fileSealDone(long se);
    public static native void fileSealFree(long se);
    public static native byte[] openFileFrame(long h, byte[] wire);
    public static native byte[] lastFp(long h);
    public static native long[] lastFrame(long h);
    public static native long hashCreate();
    public static native void hashUpdate(long h, byte[] data, int offset, int len);
    public static native byte[] hashFinal(long h);
    public static native void hashFree(long h);
}
