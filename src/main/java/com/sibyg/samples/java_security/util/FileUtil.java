package com.sibyg.samples.java_security.util;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Optional;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

@Slf4j
public class FileUtil {
    public static Optional<String> readFileToString(String filename) throws IOException {
        File file = new File(filename);

        if (!file.exists()) return Optional.empty();

        return Optional.of(FileUtils.readFileToString(file, Charset.defaultCharset()));
    }
}
