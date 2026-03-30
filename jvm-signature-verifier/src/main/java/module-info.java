/**
 * @author VISTALL
 * @since 2026-03-30
 */
module format.ripper.jvm.signature.verifier {
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.util;

    requires format.ripper.jvm.file.type.detector;

    requires org.apache.commons.io;

    requires java.net.http;

    exports com.jetbrains.signatureverifier.cf;
    exports com.jetbrains.signatureverifier.bouncycastle.cms;
    exports com.jetbrains.signatureverifier.bouncycastle.tsp;
    exports com.jetbrains.signatureverifier.crypt;
    exports com.jetbrains.signatureverifier.macho;
    exports com.jetbrains.signatureverifier.powershell;
}