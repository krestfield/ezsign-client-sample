package com.krestfield.ezsign.samples;

import com.krestfield.ezsign.EzSignClient;
import com.krestfield.ezsign.KEzSignConnectException;
import com.krestfield.ezsign.KEzSignException;
import com.krestfield.ezsign.KPathException;
import com.krestfield.ezsign.KRevocationException;
import com.krestfield.ezsign.KSigningException;
import com.krestfield.ezsign.KVerificationException;

import java.util.Base64;

/**
 * This sample demonstrates how the EzSign or PKCloud services can be called from a java client
 * A demonstration server is available at this location:
 *
 *    Server: demoapi.krestfield.com Port: 80
 *
 * And this sample targets that instance.  The demo server is up between the hours of 06:00 - 19:00 UTC
 * WARNING: This is for test purposes only, the certificates configured on the test server are for test only
 * and any data sent to this server is not protected
 *
 * More details about the EzSign and PKCloud are available here: https://www.krestfield.com
 * Questions can be directed to: support@krestfield.com
 *
 */
public class EzSignSample
{
    public static void main(String[] args)
    {
        try
        {
            // Connection to the server requires a unique authentication code
            // For the demo this is just 'password' but may change at any time.  Contact support@krestfield.com
            // to obtain the latest code
            String authenticationCode = "password";

            // Each channel on the server can be configured independently.  Some of the options available are:
            //   * The algorithm used to sign (RSA or ECDSA - post quantum algorithms coming soon...)
            //   * The signature format to produce - RAW or PKCS7
            //   *  Whether to perform revocation checking or not
            // For more details visit: https://krestfield.com/index.php/pkcloud

            // This channel generates a PKCS#7/CMS formatted signature using RSA
            String channelName = "P7_RSA_SIGN_CHANNEL";

            // Other channels available are as follows:
            //
            // To generate a PKCS#7 formatted signature using ECDSA
            // String channelName = "P7_ECDSA_SIGN_CHANNEL";

            // To generate a RAW (PKCS#1) formatted signature using RSA
            // Note that you need to call verifyRawSignature and pass the signer certificate to verify a
            // signature generated with this channel
            // String channelName = "RAW_RSA_SIGN_CHANNEL";

            // To generate a RAW signature using ECDSA
            // Note that you need to call verifyRawSignature and pass the signer certificate to verify a
            // signature generated with this channel
            // String channelName = "RAW_ECDSA_SIGN_CHANNEL";

            byte[] dataToSign = "Hello".getBytes();

            // Create the client
            EzSignClient client = new EzSignClient("demoapi.krestfield.com", 80, authenticationCode);

            // Generate a signature
            // If signing a large data set (or to ensure the original data is never sent to the server), it is
            // recommended to hash the data locally (this can be carried out using standard tools or the EzSign Client
            // Utilities).  Set this hashed data as 'dataToSign'.  The 'isDigest' parameter must then
            // be set to true to indicate the data has already been hashed (i.e. is a digest of the original data)
            byte[] signature = client.signData(channelName, dataToSign, false);
            System.out.println("Generated signature OK: " + Base64.getEncoder().encodeToString(signature));

            // Verify the signature
            // The server will carry out a full verification including certificate validation and
            // path building.  Revocation (CRL and OCSP) checking can also be performed although is not configured
            // on the demo server
            client.verifySignature(channelName, signature, dataToSign, false);
            System.out.println("Verified signature OK\n");

            // The following will show a failure as we have altered the data:
            System.out.println("We expect the next action to throw an error...");
            dataToSign = "Hell".getBytes();
            client.verifySignature(channelName, signature, dataToSign, false);

            // If verifying a raw signature, the following call must be made as the server needs to know what
            // certificate signed the data (as this is not included in a RAW signature):
            // X509Certificate signerCert = -- load the signer certificate here --;
            // client.verifyRawSignature(channelName, signature, dataToSign, false, signerCert);
        }
        catch (KEzSignException | KSigningException | KEzSignConnectException | KVerificationException | KPathException | KRevocationException e)
        {
            System.out.println("There was an error: " + e.getMessage());
        }
    }
}
