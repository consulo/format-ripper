import org.jspecify.annotations.NullMarked;
/**
 * @author VISTALL
 * @since 2026-03-30
 */
@NullMarked
module format.ripper.jvm.file.type.detector {
    requires static org.jspecify;
    
    exports com.jetbrains.util.filetype;
    exports com.jetbrains.util.filetype.elf;
    exports com.jetbrains.util.filetype.io;
}