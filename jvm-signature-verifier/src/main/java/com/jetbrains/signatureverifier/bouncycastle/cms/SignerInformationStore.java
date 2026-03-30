package com.jetbrains.signatureverifier.bouncycastle.cms;

import org.bouncycastle.cms.SignerId;
import org.bouncycastle.util.Iterable;

import java.util.*;

public class SignerInformationStore implements Iterable<SignerInformation> {
  private List<SignerInformation> all;
  private final Map<SignerId, List<SignerInformation>> table = new HashMap<>();

  public SignerInformationStore(SignerInformation signerInfo) {
    all = new ArrayList<>();
    all.add(signerInfo);
    SignerId sid = signerInfo.getSID();
    table.put(sid, all);
  }

  public SignerInformationStore(Collection<SignerInformation> signerInfos) {
    for (SignerInformation signer : signerInfos) {
      SignerId sid = signer.getSID();
      List<SignerInformation> list = table.get(sid);
      if (list == null) {
        list = new ArrayList<>();
        table.put(sid, list);
      }
      list.add(signer);
    }
    all = new ArrayList<>(signerInfos);
  }

  public SignerInformation get(SignerId selector) {
    Collection<SignerInformation> list = getSigners(selector);
    return (list == null || list.isEmpty()) ? null : list.iterator().next();
  }

  public int size() {
    return all.size();
  }

  public Collection<SignerInformation> getSigners() {
    return new ArrayList<>(all);
  }

  public Collection<SignerInformation> getSigners(SignerId selector) {
    if (selector.getIssuer() != null && selector.getSubjectKeyIdentifier() != null) {
      List<SignerInformation> results = new ArrayList<>();
      Collection<SignerInformation> match1 = getSigners(new SignerId(selector.getIssuer(), selector.getSerialNumber()));
      if (match1 != null) results.addAll(match1);
      Collection<SignerInformation> match2 = getSigners(new SignerId(selector.getSubjectKeyIdentifier()));
      if (match2 != null) results.addAll(match2);
      return results;
    } else {
      List<SignerInformation> list = table.get(selector);
      return list == null ? new ArrayList<>() : new ArrayList<>(list);
    }
  }

  @Override
  public Iterator<SignerInformation> iterator() {
    return getSigners().iterator();
  }
}
