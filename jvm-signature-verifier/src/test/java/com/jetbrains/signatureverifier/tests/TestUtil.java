package com.jetbrains.signatureverifier.tests;

import com.jetbrains.util.filetype.io.ReadUtils;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.EnumSet;
import java.util.Optional;
import java.util.stream.Stream;

public class TestUtil {

    public static SeekableByteChannel getTestByteChannel(String name) throws IOException {
        return Files.newByteChannel(getTestDataFile(name), StandardOpenOption.READ);
    }

    public static SeekableByteChannel getTestByteChannel(String dir, String name) throws IOException {
        return Files.newByteChannel(getTestDataFile(dir, name), StandardOpenOption.READ);
    }

    public static SeekableByteChannel getTestByteChannelCopy(String dir, String name) throws IOException {
        try (SeekableByteChannel ch = getTestByteChannel(dir, name)) {
            return new SeekableInMemoryByteChannel(ReadUtils.readToEnd(ch));
        }
    }

    public static InputStream getTestDataInputStream(String dir, String name) throws IOException {
        return new FileInputStream(getTestDataFile(dir, name).toFile());
    }

    public static Path getTestDataFile(String dir, String name) throws IOException {
        Path testDataFile = getTestDataDir().resolve(dir).resolve(name);
        if (Files.notExists(testDataFile)) {
            throw new RuntimeException("Test data file '" + name + "' was not found at " + testDataFile);
        }
        return testDataFile;
    }

    public static Path getTestDataFile(String name) throws IOException {
        Path dir = getTestDataDir();
        try (Stream<Path> walk = Files.walk(dir, 2)) {
            Optional<Path> path = walk.filter(p -> p.getFileName().toString().equals(name)).findFirst();
            if (!path.isPresent()) {
                throw new RuntimeException("Test data file '" + name + "' was not found at " + dir);
            }
            return path.get();
        }
    }

    private static Path getTestDataDir() {
        Path current = Paths.get(System.getProperty("user.dir"));
        while (current.getParent() != null) {
            Path dataDir = current.resolve("data");
            if (Files.isDirectory(dataDir)) {
                return dataDir;
            }
            current = current.getParent();
        }
        throw new RuntimeException("Test data directory 'data' not found from " + Paths.get(System.getProperty("user.dir")));
    }

    @SafeVarargs
    public static <T extends Enum<T>> EnumSet<T> enumSetOf(T... items) {
        if (items.length == 0) {
            throw new IllegalArgumentException("At least one item required");
        }
        EnumSet<T> set = EnumSet.of(items[0]);
        for (int i = 1; i < items.length; i++) {
            set.add(items[i]);
        }
        return set;
    }
}
