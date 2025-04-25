/*
 * Copyright © 2025 Christian Grobmeier, Piotr P. Karwasz
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.sbom.enforcer.rules;

import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.Component;
import io.github.sbom.enforcer.Component.ChecksumAlgorithm;
import io.github.sbom.enforcer.EnforcerRule;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.inject.Named;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.maven.plugin.MojoFailureException;
import org.jspecify.annotations.Nullable;

/**
 * Rules to check if the checksums present in the SBOM are correct.
 */
@Named("checksum")
public class ChecksumRule implements EnforcerRule {
    @Override
    public void execute(BillOfMaterials bom) throws MojoFailureException {
        List<String> errors = new ArrayList<>(validateChecksums(bom.getComponent()));
        for (Component dependency : bom.getDependencies()) {
            errors.addAll(validateChecksums(dependency));
        }

        if (!errors.isEmpty()) {
            String message = errors.stream()
                    .sorted()
                    .collect(Collectors.joining(
                            "\n* ",
                            "\nSBOM " + bom.getBillOfMaterials().getFile() + " contains invalid checksums:\n* ",
                            ""));
            throw new MojoFailureException(message);
        }
    }

    private static List<String> validateChecksums(Component component) {
        File file = component.getArtifact().getFile();
        if (file == null || !file.exists()) {
            return List.of("Missing file for artifact: " + component.getArtifact());
        }
        return component.getChecksums().entrySet().stream()
                .<String>mapMulti((entry, consumer) -> {
                    String error = validateChecksum(entry.getKey(), entry.getValue(), file);
                    if (error != null) {
                        consumer.accept(error);
                    }
                })
                .toList();
    }

    private static @Nullable String validateChecksum(ChecksumAlgorithm algorithm, String expectedValue, File file) {
        try {
            MessageDigest digest = DigestUtils.getDigest(algorithm.toJce());
            String computedValue = Hex.encodeHexString(DigestUtils.digest(digest, file));
            if (!expectedValue.equals(computedValue)) {
                return "Invalid " + algorithm + " checksum for file " + file.getName() + ": expecting `" + expectedValue
                        + "` but got `" + computedValue + "`";
            }
        } catch (IllegalArgumentException e) {
            return "Failed to calculate checksum for file " + file.getName() + ": algorithm " + algorithm.toJce()
                    + " is not supported.";
        } catch (IOException e) {
            return "Failed to calculate checksum for file " + file.getName() + ": " + e.getMessage();
        }
        return null;
    }
}
