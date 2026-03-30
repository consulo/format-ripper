package com.jetbrains.signatureverifier.crypt;

import com.jetbrains.signatureverifier.ILogger;
import com.jetbrains.signatureverifier.NullLogger;
import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformation;
import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;

public class SignedMessageVerifier {
  private final CrlProvider _crlProvider;
  private final ILogger _logger;

  public SignedMessageVerifier(ILogger logger) {
    this(new CrlProvider(logger), logger);
  }

  public SignedMessageVerifier(CrlProvider crlProvider, ILogger logger) {
    _crlProvider = crlProvider;
    _logger = logger != null ? logger : NullLogger.Instance;
  }

  public VerifySignatureResult VerifySignatureAsync(
    SignedMessage signedMessage,
    SignatureVerificationParams signatureVerificationParams) throws Exception {

    _logger.Trace("Verify with params: " + signatureVerificationParams);
    Store<X509CertificateHolder> certs = signedMessage.SignedData.getCertificates();
    SignerInformationStore signersStore = signedMessage.SignedData.getSignerInfos();
    return verifySignatureAsync(signersStore, certs, signatureVerificationParams);
  }

  private VerifySignatureResult verifySignatureAsync(
    SignerInformationStore signersStore,
    Store<X509CertificateHolder> certs,
    SignatureVerificationParams signatureVerificationParams) throws Exception {

    for (SignerInformation signer : signersStore.getSigners()) {
      SignerInfoVerifier siv = new SignerInfoVerifier(signer, certs, _crlProvider, _logger);
      VerifySignatureResult result = siv.VerifyAsync(signatureVerificationParams);
      if (result != VerifySignatureResult.Valid)
        return result;
    }
    return VerifySignatureResult.Valid;
  }
}
