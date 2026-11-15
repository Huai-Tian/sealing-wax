import sealing.wax.bridge.WaxNative;

public class JniSmoke {
    static int failures = 0;
    static void check(boolean c, String what) {
        if (!c) { System.out.println("FAIL: " + what); failures++; }
    }

    public static void main(String[] args) throws Exception {
        /* pairing */
        long a = WaxNative.createSession(true);
        long b = WaxNative.createSession(false);
        check(WaxNative.sessionRole(a) == 1, "role a");
        String inv = WaxNative.invite(a);
        check(inv != null && inv.length() == 72, "invite b64 len=" + (inv == null ? -1 : inv.length()));
        String rep = WaxNative.reply(b, inv);
        check(rep != null && rep.length() == 72, "reply b64 len");
        WaxNative.finish(a, rep);
        String sasA = WaxNative.sas(a), sasB = WaxNative.sas(b);
        check(sasA != null && sasA.equals(sasB) && sasB.length() == 9, "sas equal");

        /* text roundtrip */
        byte[] msg = "hello 火漆 via JNI".getBytes("UTF-8");
        String[] pieces = WaxNative.sealText(a, msg);
        check(pieces != null && pieces.length == 1, "one piece");
        byte[] back = WaxNative.openText(b, pieces[0]);
        check(java.util.Arrays.equals(back, msg), "text roundtrip");

        /* counters */
        long[] ca = WaxNative.counters(a);
        long[] cb = WaxNative.counters(b);
        check(ca[0] == 2 && ca[1] == 0 && cb[0] == 1 && cb[1] == 1, "counters " + ca[0] + "," + ca[1] + " " + cb[0] + "," + cb[1]);

        /* multi-piece + partial */
        byte[] big = new byte[6000];
        for (int i = 0; i < big.length; i++) big[i] = (byte) (i * 7 + 1);
        String[] mp = WaxNative.sealText(a, big);
        check(mp != null && mp.length == 3, "three pieces");
        check(WaxNative.openText(b, mp[0]) == null, "partial -> null");
        check(WaxNative.openText(b, mp[1]) == null, "partial -> null");
        byte[] bigBack = WaxNative.openText(b, mp[2]);
        check(java.util.Arrays.equals(bigBack, big), "multipiece roundtrip");

        /* padding on sender */
        WaxNative.setPadding(a, true, 1000);
        String[] padded = WaxNative.sealText(a, "hi".getBytes("UTF-8"));
        check(padded != null && padded.length == 1 && padded[0].length() == 1000, "padded len " + (padded == null ? -1 : padded[0].length()));
        check(new String(WaxNative.openText(b, padded[0]), "UTF-8").equals("hi"), "pad strip");
        WaxNative.setPadding(a, false, 0);

        /* charset stress through the real JNI boundary: the v2 marker
         * class — UTF-8 tails of 0x80 (一 E4B880, 呀 E59180, 😀 F09F9880,
         * 🐀 F09F9080) plus controls (😂, Latin-1, kana); the message
         * ENDS in 呀, the exact owner-reported case */
        String tricky = "😀🐀😂café über のあぱ一好呀";
        byte[] trickyBytes = tricky.getBytes("UTF-8");
        String[] ts = WaxNative.sealText(a, trickyBytes);
        check(ts != null && ts.length == 1, "charset one piece");
        byte[] trickyBack = WaxNative.openText(b, ts[0]);
        check(java.util.Arrays.equals(trickyBack, trickyBytes), "charset bytes exact");
        check(new String(trickyBack, "UTF-8").equals(tricky), "charset string exact");

        /* same with padding on: the marker carries a 0x00 */
        WaxNative.setPadding(a, true, 1000);
        String[] tsp = WaxNative.sealText(a, trickyBytes);
        check(tsp != null && tsp.length == 1 && tsp[0].length() == 1000,
              "charset padded len " + (tsp == null ? -1 : tsp[0].length()));
        check(new String(WaxNative.openText(b, tsp[0]), "UTF-8").equals(tricky),
              "charset padded roundtrip");
        WaxNative.setPadding(a, false, 0);

        /* replay */
        try {
            WaxNative.openText(b, padded[0]);
            check(false, "replay should throw");
        } catch (IllegalStateException e) {
            check("SWX_E_REPLAY".equals(e.getMessage()), "replay code " + e.getMessage());
        }

        /* role flip: mirror session opens our own frames */
        byte[] blob0 = WaxNative.exportState(a);
        byte[] mirrorBlob = WaxNative.flipStateRole(blob0);
        check(mirrorBlob.length == 60 && mirrorBlob[5] != blob0[5], "flip role byte");
        long mirror = WaxNative.importState(mirrorBlob, 1, 0);
        check(WaxNative.sessionRole(mirror) == 2, "mirror role");
        String[] own = WaxNative.sealText(a, "own frame".getBytes("UTF-8"));
        check(java.util.Arrays.equals(WaxNative.openText(mirror, own[0]), "own frame".getBytes("UTF-8")), "mirror opens own frame");
        WaxNative.freeSession(mirror);

        /* state export/import */
        long[] cA = WaxNative.counters(a);
        byte[] blob = WaxNative.exportState(a);
        check(blob != null && blob.length == 60, "blob len");
        WaxNative.freeSession(a);
        a = WaxNative.importState(blob, cA[0], cA[1]);
        check(a != 0, "import");
        String[] cont = WaxNative.sealText(a, "after import".getBytes("UTF-8"));
        check(java.util.Arrays.equals(WaxNative.openText(b, cont[0]), "after import".getBytes("UTF-8")), "continue after import");

        /* file roundtrip: chunk_size default 8MB -> single chunk here; meta inside first pt */
        byte[] meta = "photo.jpg".getBytes("UTF-8");
        byte[] fileData = new byte[1000];
        for (int i = 0; i < fileData.length; i++) fileData[i] = (byte) (i * 13 + 5);
        long se = WaxNative.fileSealBegin(a, meta, fileData.length);
        check(se != 0, "seal begin");
        check(!WaxNative.fileSealDone(se), "not done yet");
        int room = WaxNative.fileChunkRoom(se);
        check(room == fileData.length, "single-chunk room " + room);
        byte[] frame = WaxNative.fileSealChunk(se, fileData);
        check(WaxNative.fileSealDone(se), "done");
        check(frame != null && frame.length > 50 + fileData.length, "frame size");
        WaxNative.fileSealFree(se);

        byte[] pt = WaxNative.openFileFrame(b, frame);
        check(pt != null && pt.length >= 4 + meta.length + fileData.length, "file pt len " + (pt == null ? -1 : pt.length));
        int metaLen = ((pt[0] & 0xff) << 24) | ((pt[1] & 0xff) << 16) | ((pt[2] & 0xff) << 8) | (pt[3] & 0xff);
        check(metaLen == meta.length, "meta len");
        byte[] metaBack = java.util.Arrays.copyOfRange(pt, 4, 4 + metaLen);
        check(java.util.Arrays.equals(metaBack, meta), "meta bytes");
        byte[] dataBack = java.util.Arrays.copyOfRange(pt, 4 + metaLen, 4 + metaLen + fileData.length);
        check(java.util.Arrays.equals(dataBack, fileData), "file data");

        /* last frame introspection */
        byte[] fp = WaxNative.lastFp(a);
        long[] lf = WaxNative.lastFrame(a);
        check(fp != null && fp.length == 16, "fp len");
        check(lf != null && lf.length == 3 && lf[1] == 0 && lf[2] == 1, "last frame " + java.util.Arrays.toString(lf));

        /* ledger hash */
        long hh = WaxNative.hashCreate();
        WaxNative.hashUpdate(hh, frame, 0, frame.length);
        byte[] digest = WaxNative.hashFinal(hh);
        WaxNative.hashFree(hh);
        check(digest != null && digest.length == 32, "digest len");

        /* tamper -> crypto error (fresh frame: received ones hit REPLAY first) */
        long se2 = WaxNative.fileSealBegin(a, meta, 4);
        byte[] fresh = WaxNative.fileSealChunk(se2, new byte[]{1, 2, 3, 4});
        WaxNative.fileSealFree(se2);
        byte[] bad = fresh.clone();
        bad[bad.length - 1] ^= 0x01;
        try {
            WaxNative.openFileFrame(b, bad);
            check(false, "tamper should throw");
        } catch (IllegalStateException e) {
            check("SWX_E_CRYPTO".equals(e.getMessage()), "tamper code " + e.getMessage());
        }

        WaxNative.freeSession(a);
        WaxNative.freeSession(b);
        System.out.println(failures == 0 ? "JNI SMOKE: ALL PASSED" : "JNI SMOKE: " + failures + " failure(s)");
        System.exit(failures == 0 ? 0 : 1);
    }
}
