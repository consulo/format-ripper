package com.jetbrains.signatureverifier.crypt;

import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformation;
import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignedMessageVerifier {
  private static final Logger LOG = LoggerFactory.getLogger(SignedMessageVerifier.class);

  private final CrlProvider crlProvider;

  public SignedMessageVerifier() {
    this(new CrlProvider());
  }

  public SignedMessageVerifier(CrlProvider crlProvider) {
    this.crlProvider = crlProvider;
  }

  public VerifySignatureResult verifySignatureAsync(
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
      SignerInfoVerifier siv = new SignerInfoVerifier(signer, certs, crlProvider);
      VerifySignatureResult result = siv.verifyAsync(signatureVerificationParams);
      if (result != VerifySignatureResult.Valid)
        return result;
    }
    return VerifySignatureResult.Valid;
  }
}
