package com.jetbrains.signatureverifier.crypt;

import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformation;
import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignedMessageVerifier {
  private static final Logger LOG = LoggerFactory.getLogger(SignedMessageVerifier.class);

  private final CrlProvider _crlProvider;

  public SignedMessageVerifier() {
    this(new CrlProvider());
  }

  public SignedMessageVerifier(CrlProvider crlProvider) {
    _crlProvider = crlProvider;
  }

  public VerifySignatureResult VerifySignatureAsync(
    SignedMessage signedMessage,
    SignatureVerificationParams signatureVerificationParams) throws Exception {

    LOG.trace("Verify with params: {}", signatureVerificationParams);
    Store<X509CertificateHolder> certs = signedMessage.SignedData.getCertificates();
    SignerInformationStore signersStore = signedMessage.SignedData.getSignerInfos();
    return verifySignatureAsync(signersStore, certs, signatureVerificationParams);
  }

  private VerifySignatureResult verifySignatureAsync(
    SignerInformationStore signersStore,
    Store<X509CertificateHolder> certs,
    SignatureVerificationParams signatureVerificationParams) throws Exception {

    for (SignerInformation signer : signersStore.getSigners()) {
      SignerInfoVerifier siv = new SignerInfoVerifier(signer, certs, _crlProvider);
      VerifySignatureResult result = siv.VerifyAsync(signatureVerificationParams);
      if (result != VerifySignatureResult.Valid)
        return result;
    }
    return VerifySignatureResult.Valid;
  }
}
