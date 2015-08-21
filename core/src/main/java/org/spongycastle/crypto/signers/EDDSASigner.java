package org.spongycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;

import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DSA;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.math.ec.custom.djb.*;
import org.spongycastle.math.ec.ECAlgorithms;
import org.spongycastle.math.ec.ECConstants;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECMultiplier;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.ReferenceMultiplier;
import org.spongycastle.math.raw.Nat256;

import javax.xml.bind.DatatypeConverter;

public class EDDSASigner
    implements ECConstants, DSA
{
    private final DSAKCalculator kCalculator;

    private ECKeyParameters key;
    private SecureRandom    random;

    static final int b = 256;
    static final BigInteger q = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    static final BigInteger qm2 = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819947");
    static final BigInteger qp3 = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819952");
    static final BigInteger l = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
    static final BigInteger d = new BigInteger("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740");
    static final BigInteger I = new BigInteger("19681161376707505956807079304988542015446066515923890162744021073123829784752");
    static final BigInteger By = new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960");
    static final BigInteger Bx = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
    static final BigInteger[] B = {Bx.mod(q),By.mod(q)};
    static final BigInteger un = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819967");

    /**
     * Default configuration, random K values.
     */
    public EDDSASigner()
    {
        this.kCalculator = new RandomDSAKCalculator();
        StackTraceElement ste = Thread.currentThread().getStackTrace()[2];
        System.out.println("呼び出し元：" + ste.getClassName() + "#" + ste.getMethodName()+":"+ste.getLineNumber());
    }

    /**
     * Configuration with an alternate, possibly deterministic calculator of K.
     *
     * @param kCalculator a K value calculator.
     */
    public EDDSASigner(DSAKCalculator kCalculator)
    {
        this.kCalculator = kCalculator;
        StackTraceElement ste = Thread.currentThread().getStackTrace()[2];
        System.out.println("呼び出し元：" + ste.getClassName() + "#" + ste.getMethodName()+":"+ste.getLineNumber());
    }

    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        SecureRandom providedRandom = null;

        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                this.key = (ECPrivateKeyParameters)rParam.getParameters();
                providedRandom = rParam.getRandom();
            }
            else
            {
                this.key = (ECPrivateKeyParameters)param;
            }
        }
        else
        {
            this.key = (ECPublicKeyParameters)param;
        }

        this.random = initSecureRandom(forSigning && !kCalculator.isDeterministic(), providedRandom);
    }

    public static byte[] H(byte[] m) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-512");
            md.reset();
            return md.digest(m);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    static BigInteger expmod(BigInteger b, BigInteger e, BigInteger m) {
        if (e.equals(BigInteger.ZERO)) {
            return BigInteger.ONE;
        }
        BigInteger t = expmod(b, e.divide(BigInteger.valueOf(2)), m).pow(2).mod(m);
        if (e.testBit(0)) {
            t = t.multiply(b).mod(m);
        }
        return t;
    }

    static BigInteger inv(BigInteger x) {
        return expmod(x, qm2, q);
    }

    static BigInteger xrecover(BigInteger y) {
        BigInteger y2 = y.multiply(y);
        BigInteger xx = (y2.subtract(BigInteger.ONE)).multiply(inv(d.multiply(y2).add(BigInteger.ONE)));
        BigInteger x = expmod(xx, qp3.divide(BigInteger.valueOf(8)), q);
        if (!x.multiply(x).subtract(xx).mod(q).equals(BigInteger.ZERO)) x = (x.multiply(I).mod(q));
        if (!x.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) x = q.subtract(x);
        return x;
    }

    static BigInteger[] edwards(BigInteger[] P, BigInteger[] Q) {
        BigInteger x1 = P[0];
        BigInteger y1 = P[1];
        BigInteger x2 = Q[0];
        BigInteger y2 = Q[1];
        BigInteger dtemp = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);
        BigInteger x3 = ((x1.multiply(y2)).add((x2.multiply(y1)))).multiply(inv(BigInteger.ONE.add(dtemp)));
        BigInteger y3 = ((y1.multiply(y2)).add((x1.multiply(x2)))).multiply(inv(BigInteger.ONE.subtract(dtemp)));
        return new BigInteger[]{x3.mod(q), y3.mod(q)};
    }

    public static BigInteger[] scalarmult(BigInteger[] P, BigInteger e) {
        if (e.equals(BigInteger.ZERO)) {
            return new BigInteger[]{BigInteger.ZERO, BigInteger.ONE};
        }
        BigInteger[] Q = scalarmult(P, e.divide(BigInteger.valueOf(2)));
        Q = edwards(Q, Q);
        if (e.testBit(0)) Q = edwards(Q, P);
        return Q;
    }

    public static int bit(byte[] h, int i) {
        return h[i/8] >> (i%8) & 1;
    }

    public byte[] publickey(byte[] sk) {
        byte[] h = H(sk);
        BigInteger a = BigInteger.valueOf(2).pow(b-2);
        for (int i=3;i<(b-2);i++) {
            BigInteger apart = BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i)));
            a = a.add(apart);
        }
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        ECDomainParameters ec = key.getParameters();
        ECPoint pe = ec.getCurve().createPoint(Bx, By, true);
        ECPoint p = basePointMultiplier.multiply(pe, a);
        BigInteger[] A = new BigInteger[]{p.getXCoord().toBigInteger(), p.getYCoord().toBigInteger()};
        return A[1].toByteArray();
    }

    public static BigInteger Hint(byte[] m) {
        byte[] h = H(m);
        BigInteger hsum = BigInteger.ZERO;
        for (int i=0;i<2*b;i++) {
            hsum = hsum.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i))));
        }
        return hsum;
    }

    public static BigInteger Hint_gpg(byte[] m) {
        byte[] h = H(m);
        byte[] hbyte = encodeint(new BigInteger(h));
        return new BigInteger(hbyte);
    }

    static boolean isoncurve(BigInteger[] P) {
        BigInteger x = P[0];
        BigInteger y = P[1];
        BigInteger xx = x.multiply(x);
        BigInteger yy = y.multiply(y);
        BigInteger dxxyy = d.multiply(yy).multiply(xx);
        return xx.negate().add(yy).subtract(BigInteger.ONE).subtract(dxxyy).mod(q).equals(BigInteger.ZERO);
    }

    static byte[] encodeint(BigInteger y) {
        byte[] in = toByteArrayWithoutSign(y);
        byte[] out = new byte[in.length];
        for (int i=0;i<in.length;i++) {
            out[i] = in[in.length - i - 1];
        }
        return out;
    }

    static byte[] encodeint_Ed25519(BigInteger y) {
        byte[] in = y.toByteArray();
        byte[] out = new byte[in.length];
        for (int i=0;i<in.length;i++) {
            out[i] = in[in.length - i - 1];
        }
        return out;
    }

    // static byte[] encodeintWithPadding(BigInteger y, int size) {
    //     byte[] in = toByteArrayWithoutSign(y);
    //     int nsize = in.length;
    //     ByteBuffer bb = new ByteBuffer.allocate(32);
    //     for (int i=nsize; i<size; ++i)
    //         bb.put();
    //     byte[] out = new byte[in.length];
    //     for (int i=0;i<in.length;i++) {
    //         out[i] = in[in.length - i - 1];
    //     }
    //     return out;
    // }

    static byte[] encodeByte(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i=0;i<in.length;i++) {
            out[i] = in[in.length - i - 1];
        }
        return out;
    }

    // public static byte[] encodepoint(BigInteger[] P) {
    //     BigInteger x = P[0];
    //     BigInteger y = P[1];
    //     byte[] out = encodeint(y);
    //     out[0] |= (x.testBit(0) ? 0x80 : 0);
    //     return out;
    // }

    // static BigInteger[] decodepoint(byte[] s) throws Exception {
    //     byte[] ybyte = Arrays.copyOf(s, s.length);
    //     ybyte[0] &= 0x7F;
    //     BigInteger y = new BigInteger(ybyte);
    //     BigInteger x = xrecover(y);
    //     if ((x.testBit(0)?1:0) != (s[0]&0x80) )
    //     {
    //         x = q.subtract(x);
    //     }
    //     BigInteger[] P = {x,y};
    //     if (!isoncurve(P)) throw new Exception("decoding point that is not on curve");
    //     return P;
    // }

    public static BigInteger toBigIntegerWithSign(byte[] b) {
        ByteBuffer bb = ByteBuffer.allocate(b.length + 1);
        bb.put((byte)0x00).put(b);
        return new BigInteger(bb.array());
    }

    public static byte[] encodepoint(BigInteger[] P) {
        BigInteger x = P[0];
        byte[] xbyte = toByteArrayWithoutSign(x);
        BigInteger y = P[1];
        byte[] ybyte = toByteArrayWithoutSign(x);
        // byte[] ybyte = y.toByteArray();
        ByteBuffer Rsub = ByteBuffer.allocate(1 + xbyte.length + ybyte.length);
        Rsub.put((byte)0x04);
        Rsub.put(xbyte);
        Rsub.put(ybyte);
        return Rsub.array();
    }

    public static byte[] encodepoint_gpg(BigInteger[] P) {
        BigInteger x = P[0];
        BigInteger y = P[1];
        byte[] out = encodeint(y);
        out[out.length - 1] |= (x.testBit(0) ? 0x80 : 0);
        return out;
    }

    public static BigInteger[] decodepoint(byte[] s) throws Exception {
        if (s[0] == 0x04) {
            byte[] xbyte = Arrays.copyOfRange(s, 1, (1 + s.length) / 2);
            byte[] ybyte = Arrays.copyOfRange(s, (1 + s.length) / 2, s.length);
            BigInteger x = new BigInteger(xbyte);
            BigInteger y = new BigInteger(ybyte);
            BigInteger[] P = {x,y};
            if (!isoncurve(P)) throw new Exception("decoding point that is not on curve");
            return P;
        } else {
            byte[] ytmp;
            if (s[0] == 0x40)
                ytmp = Arrays.copyOfRange(s, 1, s.length);
            else
                ytmp = Arrays.copyOfRange(s, 0, s.length);
            byte[] ybyte = new byte[ytmp.length];
            for (int i=0; i<ytmp.length; ++i)
                ybyte[i] = ytmp[ytmp.length - i - 1];
            showByte(ytmp, "new encpk");
            int sign = (ybyte[0] & 0x80) > 0 ? 1  : 0;
            ybyte[0] &= 0x7F;
            BigInteger y = new BigInteger(ybyte);
            BigInteger x = xrecover(y);
            if ((x.testBit(0)?1:0) != sign )
            {
                x = q.subtract(x);
            }
            BigInteger[] P = {x,y};
            if (!isoncurve(P)) throw new Exception("decoding point that is not on curve");
            return P;
        }
    }

    public BigInteger[] generateSignature(byte[] m) {
        BigInteger d = ((ECPrivateKeyParameters)key).getD();
        byte[] sk = d.toByteArray();
        byte[] pk = publickey(sk);
        byte[] h = H(sk);
        BigInteger a = BigInteger.valueOf(2).pow(b-2);
        for (int i=3;i<(b-2);i++) {
            a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i))));
        }
        ByteBuffer rsub = ByteBuffer.allocate((b/8)+m.length);
        rsub.put(h, b/8, b/4-b/8).put(m);
        BigInteger r = Hint(rsub.array());
        r = r.mod(l);
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        ECDomainParameters ec = key.getParameters();
        ECPoint pe = ec.getCurve().createPoint(Bx, By, true);
        ECPoint p = basePointMultiplier.multiply(pe, r);
        BigInteger[] R = new BigInteger[]{p.getXCoord().toBigInteger(), p.getYCoord().toBigInteger()};
        ByteBuffer Stemp = ByteBuffer.allocate(b/4+pk.length+m.length);
        Stemp.put(R[0].toByteArray()).put(R[1].toByteArray()).put(pk).put(m);
        BigInteger S = r.add(Hint(Stemp.array()).multiply(a)).mod(l);
        return new BigInteger[]{ new BigInteger(encodepoint(R)), S};
    }

    public static void show(BigInteger b, String str) {
        ByteBuffer bb = ByteBuffer.allocate(b.toByteArray().length + 1);
        bb.put((byte)0x00).put(b.toByteArray());
        System.out.println(str + ":" + new BigInteger(bb.array()).toString(16));
    }

    public static void showByte(byte[] b, String str) {
        String res = DatatypeConverter.printHexBinary(b);
        System.out.println(str + ":" + res);
    }

    private byte[] encodepoint_Ed25519(ECFieldElement z, ECFieldElement x, ECFieldElement y) {
        ECFieldElement mz = z.invert();
        ECFieldElement mx = x.multiply(mz);
        ECFieldElement my = y.multiply(mz);
        BigInteger bx = mx.toBigInteger();
        BigInteger by = my.toBigInteger();
        BigInteger bz = z.toBigInteger();
        BigInteger mbz = mz.toBigInteger();
        System.out.println("bx" + bx.toString(16));
        System.out.println("by" + by.toString(16));
        System.out.println("bz" + bz.toString(16));
        System.out.println("mbz" + mbz.toString(16));
        byte[] byy = encodeint_Ed25519(by);
        showByte(byy, "byy");
        if (bx.testBit(0))
            byy[byy.length - 1] |= 0x80;
        return byy;
    }

    public static byte[] toByteArrayWithoutSign(BigInteger b) {
        byte[] resWithSign = b.toByteArray();
        byte[] res = Arrays.copyOfRange(resWithSign, 1, resWithSign.length);
        return res;
    }

    public byte[] toByteArrayWithPadding(BigInteger b, int size) {
        ByteBuffer bb = ByteBuffer.allocate(size);
        byte[] by = toByteArrayWithoutSign(b);
        for (int i=by.length; i<size; ++i ) {
            bb.put((byte)0x00);
        }
        bb.put(by);
        return bb.array();
    }

    public boolean verifySignature(
        byte[]      mb,
        BigInteger  Rb,
        BigInteger  Sb)
    {
        ECDomainParameters ec = key.getParameters();
        // ======
        // String pkStr = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        // byte[] encoded = DatatypeConverter.parseHexBinary(pkStr);
        // BigInteger[] A;
        // try
        // {
        //     A = decodepoint(encoded);
        // }
        // catch (Exception e)
        // {
        //     e.printStackTrace();
        //     throw new IllegalArgumentException("Given point is not on the curve.");
        // }
        // BigInteger RS = new BigInteger(
        //     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00", 16);
        // // 30440220692A7E70CF78CFB20CBDA7AE73C73D7EC4912BFDC733150C7FB58924E3DB647802203FD8C91384850F6955A1FC67D5EDB61FB60BBDC5721C3380F60A585933578805
        // byte[] rsbyte = RS.toByteArray();
        // ByteBuffer rbbuf  = ByteBuffer.allocate(32);
        // rbbuf.put(Arrays.copyOfRange(rsbyte, 1, 33));
        // byte[] rbuf = rbbuf.array();
        // ByteBuffer sbbuf  = ByteBuffer.allocate(32);
        // sbbuf.put(Arrays.copyOfRange(rsbyte, 33, 64));
        // byte[] sbuf = sbbuf.array();
        // byte[] m = new byte[]{(byte)0x72};
        // ECPoint Q = ec.getCurve().createPoint(A[0], A[1]);
        // Ed25519FieldElement EncX = (Ed25519FieldElement)Q.getXCoord();
        // Ed25519FieldElement EncY = (Ed25519FieldElement)Q.getYCoord();
        // Ed25519FieldElement EncZ = (Ed25519FieldElement)Q.getZCoord(0);
        // byte[] encpk = encodepoint_Ed25519(EncZ, EncX, EncY);
        // ======
        // byte[] m = mb;
        byte[] newmb = H(mb);
        String pkStr = "734e0c0df453a6549339d21c876c711ab723bbcf064c60e38eeff275b04aa7f9";
        byte[] m = DatatypeConverter.parseHexBinary(pkStr);
        byte[] rbuf = Rb.toByteArray();
        byte[] sbuf = Sb.toByteArray();
        ECPoint Q = ((ECPublicKeyParameters)key).getQ();
        BigInteger[] A = new BigInteger[]{Q.getXCoord().toBigInteger(), Q.getYCoord().toBigInteger()};
        Ed25519FieldElement EncX = (Ed25519FieldElement)Q.getXCoord();
        Ed25519FieldElement EncY = (Ed25519FieldElement)Q.getYCoord();
        Ed25519FieldElement EncZ = (Ed25519FieldElement)Q.getZCoord(0);
        byte[] encpk = encodepoint_Ed25519(EncZ, EncX, EncY);
        showByte(encpk, "encpk");
        showByte(rbuf, "rbuf");
        showByte(sbuf, "sbuf");
        showByte(m, "mbuf");
        showByte(mb, "mbbuf");
        showByte(newmb, "newmbbuf");
        // ======

        ECPoint pe = ec.getCurve().createPoint(Bx, By);
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        byte[] encs = encodeByte(sbuf);
        BigInteger s = new BigInteger(encs);

        ECPoint p = basePointMultiplier.multiply(pe, s);
        BigInteger[] ra = new BigInteger[]{p.getXCoord().toBigInteger(), p.getYCoord().toBigInteger()};

        ByteBuffer Stemp = ByteBuffer.allocate(b/8+b/8+m.length);
        Stemp.put(rbuf).put(encpk).put(m);
        byte[] hbyte = H( Stemp.array() );
        byte[] ench = encodeByte(hbyte);
        BigInteger h = toBigIntegerWithSign(ench);

        ECPoint pe1 = ec.getCurve().createPoint(A[0], A[1], false);
        ECPoint p1 = basePointMultiplier.multiply(pe1, h);

        ECPoint pe3 = p.subtract(p1);

        Ed25519FieldElement EdX = (Ed25519FieldElement)pe3.getXCoord();
        Ed25519FieldElement EdY = (Ed25519FieldElement)pe3.getYCoord();
        Ed25519FieldElement EdZ = (Ed25519FieldElement)pe3.getZCoord(0);

        byte[] rb = encodepoint_Ed25519(EdZ, EdX, EdY);

        BigInteger T = new BigInteger(rb);

        BigInteger R = new BigInteger(rbuf);

        showByte(rb, "rb");
        showByte(rbuf, "rbuf");

        if (!R.equals(T)) // Constant time comparison
            return false;
        return true;
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new ReferenceMultiplier();
    }


    protected SecureRandom initSecureRandom(boolean needed, SecureRandom provided)
    {
        return !needed ? null : (provided != null) ? provided : new SecureRandom();
    }
}