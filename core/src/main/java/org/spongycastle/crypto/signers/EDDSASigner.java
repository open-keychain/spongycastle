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
import org.spongycastle.math.ec.ECMultiplier;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.ReferenceMultiplier;
import org.spongycastle.math.raw.Nat256;

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
    }

    /**
     * Configuration with an alternate, possibly deterministic calculator of K.
     *
     * @param kCalculator a K value calculator.
     */
    public EDDSASigner(DSAKCalculator kCalculator)
    {
        this.kCalculator = kCalculator;
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

    static boolean isoncurve(BigInteger[] P) {
        BigInteger x = P[0];
        BigInteger y = P[1];
        BigInteger xx = x.multiply(x);
        BigInteger yy = y.multiply(y);
        BigInteger dxxyy = d.multiply(yy).multiply(xx);
        return xx.negate().add(yy).subtract(BigInteger.ONE).subtract(dxxyy).mod(q).equals(BigInteger.ZERO);
    }

    static byte[] encodeint(BigInteger y) {
        byte[] in = y.toByteArray();
        byte[] out = new byte[in.length];
        for (int i=0;i<in.length;i++) {
            out[i] = in[i];
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

    public static byte[] encodepoint(BigInteger[] P) {
        BigInteger x = P[0];
        byte[] xbyte = x.toByteArray();
        BigInteger y = P[1];
        byte[] ybyte = y.toByteArray();
        ByteBuffer Rsub = ByteBuffer.allocate(1 + xbyte.length + ybyte.length);
        Rsub.put((byte)0x04);
        Rsub.put(xbyte);
        Rsub.put(ybyte);
        return Rsub.array();
    }

    public static BigInteger[] decodepoint(byte[] s) throws Exception {
        if (s[0] == 0x40) {
            byte[] ytmp = Arrays.copyOfRange(s, 1, s.length);
            byte[] ybyte = new byte[ytmp.length];
            for (int i=0; i<ytmp.length; ++i)
                ybyte[i] = ytmp[ytmp.length - i - 1];
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
        } else if (s[0] == 0x04) {
            byte[] xbyte = Arrays.copyOfRange(s, 1, (1 + s.length) / 2);
            byte[] ybyte = Arrays.copyOfRange(s, (1 + s.length) / 2, s.length);
            BigInteger x = new BigInteger(xbyte);
            BigInteger y = new BigInteger(ybyte);
            BigInteger[] P = {x,y};
            if (!isoncurve(P)) throw new Exception("decoding point that is not on curve");
            return P;
        } else {
            throw new Exception("unknown prefix.");
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

    public boolean verifySignature(
        byte[]      m,
        BigInteger  Rb,
        BigInteger  S)
    {
        ECPoint Q = ((ECPublicKeyParameters)key).getQ();

        // byte[] pk = Q.getY().toBigInteger().toByteArray();
        // BigInteger[] R,A;
        BigInteger[] R;
        try
        {
            R = decodepoint(Rb.toByteArray());
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return false;
        }
        BigInteger[] A = new BigInteger[]{Q.getX().toBigInteger(), Q.getY().toBigInteger()};


        System.out.println("R[0]:" + R[0]);
        System.out.println("R[0]:" + R[1]);
        System.out.println("A[0]:" + A[0]);
        System.out.println("A[0]:" + A[1]);


        ByteBuffer Stemp = ByteBuffer.allocate(b/4+b/8+m.length);
        Stemp.put(R[0].toByteArray()).put(R[1].toByteArray()).put(A[1].toByteArray()).put(m);
        BigInteger h = Hint(Stemp.array());
        h = h.mod(l);
        ECDomainParameters ec = key.getParameters();
        ECPoint pe = ec.getCurve().createPoint(Bx, By, true);
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        ECPoint p = basePointMultiplier.multiply(pe, S);
        BigInteger[] ra = new BigInteger[]{p.getXCoord().toBigInteger(), p.getYCoord().toBigInteger()};
        ECPoint pe1 = ec.getCurve().createPoint(A[0], A[1], true);
        ECPoint p1 = basePointMultiplier.multiply(pe1, h);
        BigInteger[] As = new BigInteger[]{p1.getXCoord().toBigInteger(), p1.getYCoord().toBigInteger()};
        BigInteger[] rb = edwards(R,As);
        if (!ra[0].equals(rb[0]) || !ra[1].equals(rb[1])) // Constant time comparison
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