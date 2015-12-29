package org.spongycastle.operator.test;

import junit.framework.TestCase;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.AlgorithmNameFinder;
import org.spongycastle.operator.DefaultAlgorithmNameFinder;

public class AllTests
    extends TestCase
{
    private static final byte[] TEST_DATA = "Hello world!".getBytes();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String TEST_DATA_HOME = "bc.test.data.home";

    public void testAlgorithmNameFinder()
        throws Exception
    {
        AlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();

        assertTrue(nameFinder.hasAlgorithmName(OIWObjectIdentifiers.elGamalAlgorithm));
        assertFalse(nameFinder.hasAlgorithmName(Extension.authorityKeyIdentifier));

        assertEquals(nameFinder.getAlgorithmName(OIWObjectIdentifiers.elGamalAlgorithm), "ELGAMAL");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.rsaEncryption), "RSA");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.id_RSAES_OAEP), "RSAOAEP");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.md5), "MD5");
        assertEquals(nameFinder.getAlgorithmName(OIWObjectIdentifiers.idSHA1), "SHA1");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha224), "SHA224");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha256), "SHA256");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha384), "SHA384");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha512), "SHA512");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha512WithRSAEncryption), "SHA512WITHRSA");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.id_RSASSA_PSS), "RSAPSS");
        assertEquals(nameFinder.getAlgorithmName(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160), "RIPEMD160WITHRSA");
        assertEquals(nameFinder.getAlgorithmName(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, DERNull.INSTANCE)), "ELGAMAL");
        assertEquals(nameFinder.getAlgorithmName(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)), "RSA");

        assertEquals(nameFinder.getAlgorithmName(Extension.authorityKeyIdentifier), Extension.authorityKeyIdentifier.getId());
    }

}