package org.spongycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DSA;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.math.ec.ECAlgorithms;
import org.spongycastle.math.ec.ECConstants;
import org.spongycastle.math.ec.ECMultiplier;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointCombMultiplier;

/**
 * EC-DSA as described in X9.62
 */
public class EdDSASigner
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
    public EdDSASigner()
    {
        this.kCalculator = new RandomDSAKCalculator();
    }

    /**
     * Configuration with an alternate, possibly deterministic calculator of K.
     *
     * @param kCalculator a K value calculator.
     */
    public EdDSASigner(DSAKCalculator kCalculator)
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

    static byte[] H(byte[] m) {
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

    static BigInteger[] scalarmult(BigInteger[] P, BigInteger e) {
        if (e.equals(BigInteger.ZERO)) {
            return new BigInteger[]{BigInteger.ZERO, BigInteger.ONE};
        }
        BigInteger[] Q = scalarmult(P, e.divide(BigInteger.valueOf(2)));
        Q = edwards(Q, Q);
        if (e.testBit(0)) Q = edwards(Q, P);
        return Q;
    }

    public static byte[] encodeint(BigInteger y) {
        byte[] in = y.toByteArray();
        byte[] out = new byte[in.length];
        for (int i=0;i<in.length;i++) {
            out[i] = in[in.length-1-i];
        }
        return out;
    }

    public static byte[] encodepoint(BigInteger[] P) {
        BigInteger x = P[0];
        BigInteger y = P[1];
        byte[] out = encodeint(y);
        out[out.length-1] |= (x.testBit(0) ? 0x80 : 0);
        return out;
    }

    public static int bit(byte[] h, int i) {
        return h[i/8] >> (i%8) & 1;
    }

    public static byte[] publickey(byte[] sk) {
        byte[] h = H(sk);
        BigInteger a = BigInteger.valueOf(2).pow(b-2);
        for (int i=3;i<(b-2);i++) {
            BigInteger apart = BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i)));
            a = a.add(apart);
        }
        BigInteger[] A = scalarmult(B,a);
        return encodepoint(A);
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

    static BigInteger decodeint(byte[] s) {
        byte[] out = new byte[s.length];
        for (int i=0;i<s.length;i++) {
            out[i] = s[s.length-1-i];
        }
        return new BigInteger(out).and(un);
    }

    static BigInteger[] decodepoint(byte[] s) throws Exception {
        byte[] ybyte = new byte[s.length];
        for (int i=0;i<s.length;i++) {
            ybyte[i] = s[s.length-1-i];
        }
        BigInteger y = new BigInteger(ybyte).and(un);
        BigInteger x = xrecover(y);
        if ((x.testBit(0)?1:0) != bit(s, b-1)) {
            x = q.subtract(x);
        }
        BigInteger[] P = {x,y};
        if (!isoncurve(P)) throw new Exception("decoding point that is not on curve");
        return P;
    }

    // 5.3 pg 28
    /**
     * generate a signature for the given message using the key we were
     * initialised with. For conventional DSA the message should be a SHA-1
     * hash of the message of interest.
     *
     * @param message the message that will be verified later.
     */
    public BigInteger[] generateSignature(byte[] m) {
        BigInteger d = ((ECPrivateKeyParameters)key).getD();
        byte[] sk = d.toByteArray();
        if (sk[0] == 0) {
            byte[] tmp = new byte[sk.length - 1];
            System.arraycopy(sk, 1, tmp, 0, tmp.length);
            sk = tmp;
        }
        byte[] pk = publickey(sk);
        byte[] h = H(sk);
        BigInteger a = BigInteger.valueOf(2).pow(b-2);
        for (int i=3;i<(b-2);i++) {
            a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i))));
        }
        ByteBuffer rsub = ByteBuffer.allocate((b/8)+m.length);
        rsub.put(h, b/8, b/4-b/8).put(m);
        BigInteger r = Hint(rsub.array());
        BigInteger[] R = scalarmult(B,r);
        ByteBuffer Stemp = ByteBuffer.allocate(32+pk.length+m.length);
        Stemp.put(encodepoint(R)).put(pk).put(m);
        BigInteger S = r.add(Hint(Stemp.array()).multiply(a)).mod(l);
        return new BigInteger[]{ new BigInteger(encodepoint(R)), S };
    }

    // 5.4 pg 29
    /**
     * return true if the value r and s represent a DSA signature for
     * the passed in message (for standard DSA the message should be
     * a SHA-1 hash of the real message to be verified).
     */
    public boolean verifySignature(
        byte[]      m,
        BigInteger  r,
        BigInteger  bS)
    {
        BigInteger d = ((ECPrivateKeyParameters)key).getD();
        byte[] sk = d.toByteArray();
        if (sk[0] == 0) {
            byte[] tmp = new byte[sk.length - 1];
            System.arraycopy(sk, 1, tmp, 0, tmp.length);
            sk = tmp;
        }
        byte[] pk = publickey(sk);

        byte[] s = bS.toByteArray();
        if (s[0] == 0) {
            byte[] tmp = new byte[s.length - 1];
            System.arraycopy(s, 1, tmp, 0, tmp.length);
            s = tmp;
        }
        if (s.length != b/4 || pk.length != b/8)
        {
            return false;
        }
        byte[] Rbyte = Arrays.copyOfRange(s, 0, b/8);
        BigInteger[] R,A;
        try
        {
            R = decodepoint(Rbyte);
            A = decodepoint(pk);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return false;
        }
        byte[] Sbyte = Arrays.copyOfRange(s, b/8, b/4);
        BigInteger S = decodeint(Sbyte);
        ByteBuffer Stemp = ByteBuffer.allocate(32+pk.length+m.length);
        Stemp.put(encodepoint(R)).put(pk).put(m);
        BigInteger h = Hint(Stemp.array());
        BigInteger[] ra = scalarmult(B,S);
        BigInteger[] rb = edwards(R,scalarmult(A,h));
        if (!ra[0].equals(rb[0]) || !ra[1].equals(rb[1])) // Constant time comparison
            return false;
        return true;
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }

    protected SecureRandom initSecureRandom(boolean needed, SecureRandom provided)
    {
        return !needed ? null : (provided != null) ? provided : new SecureRandom();
    }
}