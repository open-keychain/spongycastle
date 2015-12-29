package org.spongycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;

import org.spongycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.spongycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.spongycastle.crypto.params.SRP6GroupParameters;
import org.spongycastle.crypto.tls.AlertDescription;
import org.spongycastle.crypto.tls.AlertLevel;
import org.spongycastle.crypto.tls.HashAlgorithm;
import org.spongycastle.crypto.tls.ProtocolVersion;
import org.spongycastle.crypto.tls.SRPTlsServer;
import org.spongycastle.crypto.tls.SignatureAlgorithm;
import org.spongycastle.crypto.tls.SimulatedTlsSRPIdentityManager;
import org.spongycastle.crypto.tls.TlsSRPIdentityManager;
import org.spongycastle.crypto.tls.TlsSRPLoginParameters;
import org.spongycastle.crypto.tls.TlsSignerCredentials;
import org.spongycastle.crypto.tls.TlsUtils;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.Strings;

class MockSRPTlsServer
    extends SRPTlsServer
{
    static final SRP6GroupParameters TEST_GROUP = SRP6StandardGroups.rfc5054_1024;
    static final byte[] TEST_IDENTITY = Strings.toUTF8ByteArray("client");
    static final byte[] TEST_PASSWORD = Strings.toUTF8ByteArray("password");
    static final byte[] TEST_SALT = Strings.toUTF8ByteArray("salt");
    static final byte[] TEST_SEED_KEY = Strings.toUTF8ByteArray("seed_key");

    MockSRPTlsServer()
    {
        super(new MyIdentityManager());
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-SRP server raised alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
        if (message != null)
        {
            out.println("> " + message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-SRP server received alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        byte[] srpIdentity = context.getSecurityParameters().getSRPIdentity();
        if (srpIdentity != null)
        {
            String name = Strings.fromUTF8ByteArray(srpIdentity);
            System.out.println("TLS-SRP server completed handshake for SRP identity: " + name);
        }
    }

    protected ProtocolVersion getMaximumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    protected ProtocolVersion getMinimumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS-SRP server negotiated " + serverVersion);

        return serverVersion;
    }

    protected TlsSignerCredentials getDSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.dsa,
            "x509-server-dsa.pem", "x509-server-key-dsa.pem");
    }

    protected TlsSignerCredentials getRSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.rsa,
            "x509-server.pem", "x509-server-key.pem");
    }

    static class MyIdentityManager
        implements TlsSRPIdentityManager
    {
        protected SimulatedTlsSRPIdentityManager unknownIdentityManager = SimulatedTlsSRPIdentityManager.getRFC5054Default(
            TEST_GROUP, TEST_SEED_KEY);

        public TlsSRPLoginParameters getLoginParameters(byte[] identity)
        {
            if (Arrays.areEqual(TEST_IDENTITY, identity))
            {
                SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
                verifierGenerator.init(TEST_GROUP, TlsUtils.createHash(HashAlgorithm.sha1));

                BigInteger verifier = verifierGenerator.generateVerifier(TEST_SALT, identity, TEST_PASSWORD);

                return new TlsSRPLoginParameters(TEST_GROUP, verifier, TEST_SALT);
            }

            return unknownIdentityManager.getLoginParameters(identity);
        }
    }
}
