import sealing.wax.bridge.WaxNative;

public class JniSmoke {
    static int failures = 0;
    static void check(boolean c, String what) {
        if (!c) { System.out.println("FAIL: " + what); failures++; }
    }

    /* ---- full .swx container round-trip (on-device file transfer was never
     * host-covered; replays the app's sealFile / inspectSwx / peekSwxMeta /
     * decryptSwx / SwxReader logic 1:1). Fresh pairing, one text message
     * first (counter consumption), then the file: multi-chunk (> 8 MiB) or
     * single-chunk, plain or padded (the padded single chunk blows up to
     * the full 8 MiB bucket). ---- */
    static void containerRoundtrip(byte[] secret, boolean padding, int fileLen,
                                   int expectChunks, String label) throws Exception {
        long sa = WaxNative.createSession(true);
        long sb = WaxNative.createSession(false);
        String inv = WaxNative.invite(sa, secret);
        WaxNative.finish(sa, WaxNative.reply(sb, inv, secret));
        check(WaxNative.sas(sa).equals(WaxNative.sas(sb)), label + ": sas");
        if (padding) WaxNative.setPadding(sa, true, 200);

        /* one text message first: real conversations consume counters
         * before any file goes out */
        WaxNative.sealText(sa, "hi before file".getBytes("UTF-8"));

        /* sealFile: [4B BE len][frame] * n */
        byte[] fileData = new byte[fileLen];
        for (int i = 0; i < fileLen; i++) fileData[i] = (byte) (i * 31 + 7);
        String metaJson = "{\"name\":\"big.bin\",\"size\":" + fileLen + "}";
        java.io.ByteArrayOutputStream swx = new java.io.ByteArrayOutputStream();
        long se = WaxNative.fileSealBegin(sa, metaJson.getBytes("UTF-8"), fileLen);
        check(se != 0, label + ": seal begin");
        int chunks = 0;
        java.io.ByteArrayInputStream fin = new java.io.ByteArrayInputStream(fileData);
        while (!WaxNative.fileSealDone(se)) {
            int room = WaxNative.fileChunkRoom(se);
            byte[] buf = new byte[room];
            for (int got = 0; got < room; ) {
                int n = fin.read(buf, got, room - got);
                if (n < 0) throw new IllegalStateException("source shorter than declared");
                got += n;
            }
            byte[] fr = WaxNative.fileSealChunk(se, buf);
            chunks++;
            swx.write((fr.length >>> 24) & 0xff);
            swx.write((fr.length >>> 16) & 0xff);
            swx.write((fr.length >>> 8) & 0xff);
            swx.write(fr.length & 0xff);
            swx.write(fr);
        }
        WaxNative.fileSealFree(se);
        check(chunks == expectChunks, label + ": chunk count " + chunks);

        /* inspectSwx: BLAKE2b over the whole container */
        byte[] container = swx.toByteArray();
        long hh = WaxNative.hashCreate();
        WaxNative.hashUpdate(hh, container, 0, container.length);
        byte[] hash = WaxNative.hashFinal(hh);
        WaxNative.hashFree(hh);
        check(hash != null && hash.length == 32, label + ": hash len");

        /* peekSwxMeta: scratch #1 reads the first frame only */
        java.io.ByteArrayInputStream cin = new java.io.ByteArrayInputStream(container);
        byte[] hdr = new byte[4];
        check(cin.read(hdr, 0, 4) == 4, label + ": peek prefix");
        int flen = ((hdr[0] & 0xff) << 24) | ((hdr[1] & 0xff) << 16) | ((hdr[2] & 0xff) << 8) | (hdr[3] & 0xff);
        check(flen >= 66 && flen <= 8 * 1024 * 1024 + 82, label + ": peek record len " + flen);
        byte[] first = new byte[flen];
        for (int got = 0; got < flen; ) {
            int n = cin.read(first, got, flen - got);
            if (n < 0) throw new IllegalStateException("peek truncated");
            got += n;
        }
        long peekScratch = WaxNative.importState(WaxNative.exportState(sb), 1, 0);
        byte[] ppt = WaxNative.openFileFrame(peekScratch, first);
        WaxNative.freeSession(peekScratch);
        int pml = ((ppt[0] & 0xff) << 24) | ((ppt[1] & 0xff) << 16) | ((ppt[2] & 0xff) << 8) | (ppt[3] & 0xff);
        check(pml >= 1 && pml <= ppt.length - 4, label + ": peek meta len " + pml);
        String pm = new String(ppt, 4, pml, "UTF-8");
        check(pm.contains("\"big.bin\"") && pm.contains(String.valueOf(fileLen)),
              label + ": peek meta " + pm);

        /* decryptSwx: scratch #2, the SwxReader walk with every Kotlin
         * assertion replayed */
        cin = new java.io.ByteArrayInputStream(container);
        long mirror = WaxNative.importState(WaxNative.exportState(sb), 1, 0);
        java.io.ByteArrayOutputStream plain = new java.io.ByteArrayOutputStream();
        long remaining = -1, written = 0, expectedIdx = 0, total = -1;
        String seenMeta = null;
        try {
            while (cin.read(hdr, 0, 4) == 4) {
                int len = ((hdr[0] & 0xff) << 24) | ((hdr[1] & 0xff) << 16) | ((hdr[2] & 0xff) << 8) | (hdr[3] & 0xff);
                if (len < 66 || len > 8 * 1024 * 1024 + 82)
                    throw new IllegalStateException("record length broken: " + len);
                byte[] fr = new byte[len];
                for (int got = 0; got < len; ) {
                    int n = cin.read(fr, got, len - got);
                    if (n < 0) throw new IllegalStateException("truncated");
                    got += n;
                }
                byte[] pt = WaxNative.openFileFrame(mirror, fr);
                long[] info = WaxNative.lastFrame(mirror);
                if (total < 0) {
                    total = info[2];
                    if (total < 1) throw new IllegalStateException("total broken");
                } else if (info[2] != total) {
                    throw new IllegalStateException("total mismatch");
                }
                if (info[1] != expectedIdx)
                    throw new IllegalStateException("chunk out of order: " + info[1] + " != " + expectedIdx);
                if (seenMeta == null) {
                    int ml = ((pt[0] & 0xff) << 24) | ((pt[1] & 0xff) << 16) | ((pt[2] & 0xff) << 8) | (pt[3] & 0xff);
                    if (ml < 1 || ml > pt.length - 4) throw new IllegalStateException("meta broken");
                    String mj = new String(pt, 4, ml, "UTF-8");
                    int start = 4 + ml;
                    /* name + size out of the JSON, then trim by size */
                    int q1 = mj.indexOf("\"size\":") + 7;
                    int q2 = mj.indexOf('}', q1);
                    remaining = Long.parseLong(mj.substring(q1, q2).trim());
                    long take = Math.min((long) pt.length - start, remaining);
                    /* write(buf, off, LEN) — keep byte-faithful to the
                     * Kotlin decryptSwx source: a diverging "cleanup" here
                     * once hid a real off/len bug from this very test. */
                    plain.write(pt, start, (int) take);
                    remaining -= take;
                    written += take;
                    seenMeta = mj;
                } else {
                    long take = Math.min((long) pt.length, remaining);
                    if (take > 0) plain.write(pt, 0, (int) take);
                    remaining -= take;
                    written += take;
                }
                expectedIdx++;
            }
        } finally {
            WaxNative.freeSession(mirror);
        }
        if (expectedIdx != total) throw new IllegalStateException("missing chunks");
        if (remaining != 0) throw new IllegalStateException("data short by " + remaining);
        check(written == fileLen, label + ": written " + written + " != " + fileLen);
        check(java.util.Arrays.equals(plain.toByteArray(), fileData),
              label + ": roundtrip bytes");

        WaxNative.freeSession(sa);
        WaxNative.freeSession(sb);
        System.out.println("  (" + label + " ok: " + chunks + " chunks, " + container.length + " B container)");
    }

    public static void main(String[] args) throws Exception {
        byte[] secret = "火漆配对暗号".getBytes("UTF-8");

        /* pairing (PAKE): invite = 32B share (44 chars), reply = 64B
         * share||confirm (88 chars) */
        long a = WaxNative.createSession(true);
        long b = WaxNative.createSession(false);
        check(WaxNative.sessionRole(a) == 1, "role a");
        String inv = WaxNative.invite(a, secret);
        check(inv != null && inv.length() == 44, "invite b64 len=" + (inv == null ? -1 : inv.length()));
        String rep = WaxNative.reply(b, inv, secret);
        check(rep != null && rep.length() == 88, "reply b64 len=" + (rep == null ? -1 : rep.length()));
        WaxNative.finish(a, rep);
        String sasA = WaxNative.sas(a), sasB = WaxNative.sas(b);
        check(sasA != null && sasA.equals(sasB) && sasB.length() == 9, "sas equal");

        /* wrong 暗号: B replies fine locally, A's finish must reject */
        long w1 = WaxNative.createSession(true);
        long w2 = WaxNative.createSession(false);
        String wInv = WaxNative.invite(w1, secret);
        byte[] badSecret = "错误的暗号".getBytes("UTF-8");
        String wRep = WaxNative.reply(w2, wInv, badSecret);
        check(wRep != null && wRep.length() == 88, "wrong-secret reply produced");
        try {
            WaxNative.finish(w1, wRep);
            check(false, "wrong secret must throw");
        } catch (IllegalStateException e) {
            check("SWX_E_CRYPTO".equals(e.getMessage()), "wrong secret code " + e.getMessage());
        }
        WaxNative.freeSession(w1);
        WaxNative.freeSession(w2);

        /* length confusion on FRESH sessions: invite pasted as reply and
         * reply pasted as invite (lengths are the only format) */
        long f1 = WaxNative.createSession(true);
        long f2 = WaxNative.createSession(false);
        try {
            WaxNative.finish(f1, inv);
            check(false, "invite-as-reply must throw");
        } catch (IllegalStateException e) {
            check("SWX_E_FORMAT".equals(e.getMessage()), "invite-as-reply code " + e.getMessage());
        }
        try {
            WaxNative.reply(f2, rep, secret);
            check(false, "reply-as-invite must throw");
        } catch (IllegalStateException e) {
            check("SWX_E_FORMAT".equals(e.getMessage()), "reply-as-invite code " + e.getMessage());
        }
        WaxNative.freeSession(f1);
        WaxNative.freeSession(f2);

        /* 公共会话 (§5): a fixed gate seed reproduces a byte-identical
         * static invite across independent armed sessions; a client pairs
         * against it through the ordinary join path, and a second client
         * against a re-armed gate gets an independent key (cross-open
         * dies at the masked header) and a fresh SAS. */
        java.util.Base64.Encoder enc = java.util.Base64.getEncoder();
        byte[] seed = new byte[64];
        for (int i = 0; i < 64; i++) seed[i] = (byte) (i * 11 + 3);
        String seedB64 = enc.encodeToString(seed);
        long g1 = WaxNative.createSession(true);
        String code1 = WaxNative.inviteSeeded(g1, secret, seedB64);
        check(code1 != null && code1.length() == 44, "static invite len");
        long g2 = WaxNative.createSession(true);
        check(code1.equals(WaxNative.inviteSeeded(g2, secret, seedB64)),
              "static invite reproducible");
        WaxNative.freeSession(g2);
        long c1 = WaxNative.createSession(false);
        String rep1 = WaxNative.reply(c1, code1, secret);
        WaxNative.finish(g1, rep1);
        String sasG1 = WaxNative.sas(g1);
        check(sasG1.equals(WaxNative.sas(c1)), "gate sas equal");
        long g3 = WaxNative.createSession(true);
        check(code1.equals(WaxNative.inviteSeeded(g3, secret, seedB64)),
              "static invite survives graduation");
        long c2 = WaxNative.createSession(false);
        String rep2 = WaxNative.reply(c2, code1, secret);
        WaxNative.finish(g3, rep2);
        check(!sasG1.equals(WaxNative.sas(g3)), "per-client fresh sas");
        byte[] gm = "仅客户1可见".getBytes("UTF-8");
        String[] gateMsg = WaxNative.sealText(g1, gm);
        try {
            WaxNative.openText(c2, gateMsg[0]);
            check(false, "cross-session open must throw");
        } catch (IllegalStateException e) {
            check("SWX_E_FORMAT".equals(e.getMessage()),
                  "cross-session code " + e.getMessage());
        }
        long gb = WaxNative.createSession(true);
        try {
            WaxNative.inviteSeeded(gb, secret, "not-base64!");
            check(false, "bad seed must throw");
        } catch (IllegalStateException e) {
            check(e.getMessage() != null && e.getMessage().startsWith("SWX_E_"),
                  "bad seed code " + e.getMessage());
        }
        WaxNative.freeSession(gb);
        WaxNative.freeSession(g1);
        WaxNative.freeSession(c1);
        WaxNative.freeSession(g3);
        WaxNative.freeSession(c2);

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

        /* out-of-order reassembly (对号入座式组装,2026-11): same-fingerprint
         * in-flight pieces fill their slots in any arrival order (arrival
         * 3,1,4,2 here); reasmState reports honest progress; a piece of the
         * completed message REPLAYs (cross-message hwm unchanged) */
        {
            StringBuilder oos = new StringBuilder();
            for (int i = 0; i < 3000; i++) oos.append('序');  /* 9000 B → 4 */
            byte[] ooMsg = oos.toString().getBytes("UTF-8");
            String[] op = WaxNative.sealText(a, ooMsg);
            check(op.length == 4, "oo piece count " + op.length);
            check(WaxNative.openText(b, op[2]) == null, "oo: piece 3 partial");
            long[] rs = WaxNative.reasmState(b);
            check(rs[0] == 1 && rs[1] == 4, "oo reasm 1/4: " + rs[0] + "/" + rs[1]);
            check(WaxNative.openText(b, op[0]) == null, "oo: piece 1 partial");
            rs = WaxNative.reasmState(b);
            check(rs[0] == 2 && rs[1] == 4, "oo reasm 2/4: " + rs[0] + "/" + rs[1]);
            check(WaxNative.openText(b, op[3]) == null, "oo: piece 4 partial");
            rs = WaxNative.reasmState(b);
            check(rs[0] == 3 && rs[1] == 4, "oo reasm 3/4: " + rs[0] + "/" + rs[1]);
            byte[] ooBack = WaxNative.openText(b, op[1]);  /* last slot assembles */
            check(java.util.Arrays.equals(ooBack, ooMsg), "oo assembles byte-exact");
            rs = WaxNative.reasmState(b);
            check(rs[0] == 0 && rs[1] == 0, "oo reasm idle");
            try {
                WaxNative.openText(b, op[2]);
                check(false, "completed-message piece must REPLAY");
            } catch (IllegalStateException e) {
                check("SWX_E_REPLAY".equals(e.getMessage()),
                      "oo replay code " + e.getMessage());
            }
        }

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

        /* file re-import idempotency (decryptSwx fix): a live open consumed
         * the counter above, so a second live open of the same frame replays
         * (the old in-app bug); decryptSwx now opens on a fresh throwaway
         * mirror per import (exportState -> importState with counters pinned
         * at 1/0), which is idempotent, and the mirrors never touch the
         * live session's high-water — a newer frame still opens live */
        try {
            WaxNative.openFileFrame(b, frame);
            check(false, "second live open should REPLAY");
        } catch (IllegalStateException e) {
            check("SWX_E_REPLAY".equals(e.getMessage()), "live re-open code " + e.getMessage());
        }
        long bMirror = WaxNative.importState(WaxNative.exportState(b), 1, 0);
        check(java.util.Arrays.equals(WaxNative.openFileFrame(bMirror, frame), pt),
              "mirror re-import bytes");
        WaxNative.freeSession(bMirror);
        long bMirror2 = WaxNative.importState(WaxNative.exportState(b), 1, 0);
        check(java.util.Arrays.equals(WaxNative.openFileFrame(bMirror2, frame), pt),
              "mirror re-import again");
        WaxNative.freeSession(bMirror2);
        long se3 = WaxNative.fileSealBegin(a, meta, 3);
        byte[] newer = WaxNative.fileSealChunk(se3, new byte[]{9, 8, 7});
        WaxNative.fileSealFree(se3);
        check(WaxNative.openFileFrame(b, newer).length >= 4 + meta.length + 3,
              "live accepts newer frame");

        WaxNative.freeSession(a);
        WaxNative.freeSession(b);

        /* full .swx container round-trips: multi-chunk (3 frames over the
         * 8 MiB boundary) and single-chunk, plain and padded — the app's
         * exact file path; the padded single-chunk case is where the final
         * chunk blows up to the full 8 MiB bucket */
        containerRoundtrip(secret, false, 20 * 1024 * 1024 + 12345, 3, "container plain");
        containerRoundtrip(secret, true, 20 * 1024 * 1024 + 12345, 3, "container padded");
        containerRoundtrip(secret, false, 12345, 1, "container single plain");
        containerRoundtrip(secret, true, 12345, 1, "container single padded");

        System.out.println(failures == 0 ? "JNI SMOKE: ALL PASSED" : "JNI SMOKE: " + failures + " failure(s)");
        System.exit(failures == 0 ? 0 : 1);
    }
}
