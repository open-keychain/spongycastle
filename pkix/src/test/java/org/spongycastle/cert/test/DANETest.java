package org.spongycastle.cert.test;

import java.io.IOException;
import java.security.Security;

import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.dane.DANEEntry;
import org.spongycastle.cert.dane.DANEEntryFactory;
import org.spongycastle.cert.dane.DANEException;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.test.SimpleTest;

public class DANETest
    extends SimpleTest
{
    byte[]  randomCert = Base64.decode(
            "MIIDbDCCAtWgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
                + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
                + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
                + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
                + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU1MzNaFw0wMTA2"
                + "MDIwNzU1MzNaMIG3MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
                + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
                + "dGQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEVMBMGA1UEAxMMQ29u"
                + "bmVjdCA0IENBMSgwJgYJKoZIhvcNAQkBFhl3ZWJtYXN0ZXJAY29ubmVjdDQuY29t"
                + "LmF1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgs5ptNG6Qv1ZpCDuUNGmv"
                + "rhjqMDPd3ri8JzZNRiiFlBA4e6/ReaO1U8ASewDeQMH6i9R6degFdQRLngbuJP0s"
                + "xcEE+SksEWNvygfzLwV9J/q+TQDyJYK52utb++lS0b48A1KPLwEsyL6kOAgelbur"
                + "ukwxowprKUIV7Knf1ajetQIDAQABo4GFMIGCMCQGA1UdEQQdMBuBGXdlYm1hc3Rl"
                + "ckBjb25uZWN0NC5jb20uYXUwDwYDVR0TBAgwBgEB/wIBADA2BglghkgBhvhCAQ0E"
                + "KRYnbW9kX3NzbCBnZW5lcmF0ZWQgY3VzdG9tIENBIGNlcnRpZmljYXRlMBEGCWCG"
                + "SAGG+EIBAQQEAwICBDANBgkqhkiG9w0BAQQFAAOBgQCsGvfdghH8pPhlwm1r3pQk"
                + "msnLAVIBb01EhbXm2861iXZfWqGQjrGAaA0ZpXNk9oo110yxoqEoSJSzniZa7Xtz"
                + "soTwNUpE0SLHvWf/SlKdFWlzXA+vOZbzEv4UmjeelekTm7lc01EEa5QRVzOxHFtQ"
                + "DhkaJ8VqOMajkQFma2r9iA==");

    public String getName()
    {
        return "DANETest";
    }

    private void shouldCreateDANEEntry()
        throws IOException, DANEException
    {
        DANEEntryFactory daneEntryFactory = new DANEEntryFactory(new SHA224DigestCalculator());

        DANEEntry entry = daneEntryFactory.createEntry("test@test.com", new X509CertificateHolder(randomCert));

        if (!DANEEntry.isValidCertificate(entry.getRDATA()))
        {
            fail("encoding error in RDATA");
        }

        if (!"90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809._smimecert.test.com".equals(entry.getDomainName()))
        {
            fail("domain name associated with entry wrong");
        }

        byte[] rdata = entry.getRDATA();
        byte[] certData = new byte[rdata.length - 3];

        System.arraycopy(rdata, 3, certData, 0, certData.length);

        if (!Arrays.areEqual(certData, randomCert))
        {
            fail("certificate encoding does not match");
        }
    }

    public void performTest()
        throws Exception
    {
         shouldCreateDANEEntry();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new DANETest());
    }
}
