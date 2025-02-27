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
import java.util.Map;
import javax.inject.Named;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.maven.plugin.MojoFailureException;

/**
 * Rules to check if the checksums present in the SBOM are correct.
 */
@Named("checksum")
public class ChecksumRule implements EnforcerRule {
    @Override
    public void execute(BillOfMaterials bom) throws MojoFailureException {
        checkChecksums(bom.getComponent());
        for (Component dependency : bom.getDependencies()) {
            checkChecksums(dependency);
        }
    }

    private static void checkChecksums(Component component) throws MojoFailureException {
        File file = component.getArtifact().getFile();
        if (!file.exists()) {
            throw new MojoFailureException("Missing file for artifact " + component.getArtifact());
        }
        for (Map.Entry<ChecksumAlgorithm, String> entry :
                component.getChecksums().entrySet()) {
            checkChecksum(entry.getKey(), entry.getValue(), file);
        }
    }

    private static void checkChecksum(ChecksumAlgorithm algorithm, String expectedValue, File file)
            throws MojoFailureException {
        try {
            MessageDigest digest = DigestUtils.getDigest(algorithm.toJce());
            String computedValue = Hex.encodeHexString(DigestUtils.digest(digest, file));
            if (!expectedValue.equals(computedValue)) {
                throw new MojoFailureException(
                        null,
                        "Checksum failed for file " + file.getName(),
                        "Expecting `" + expectedValue + "` but got `" + computedValue + "`");
            }
        } catch (IllegalArgumentException e) {
            throw new MojoFailureException(
                    "Failed to calculate checksum for file " + file.getName() + ": algorithm " + algorithm.toJce()
                            + " is not supported.",
                    e);
        } catch (IOException e) {
            throw new MojoFailureException(
                    "Failed to calculate checksum for file " + file.getName() + ": I/O error.", e);
        }
    }
}
