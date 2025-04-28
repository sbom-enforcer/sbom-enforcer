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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.Component;
import io.github.sbom.enforcer.Component.ChecksumAlgorithm;
import io.github.sbom.enforcer.support.DefaultBillOfMaterials;
import io.github.sbom.enforcer.support.DefaultComponent;
import java.io.File;
import java.net.URL;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import org.apache.maven.plugin.MojoFailureException;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ChecksumRuleTest {

    private static final File mockArtifact;
    private static final File nonExistentArtifact = new File("non-existent-artifact");
    // Checksums for the artifact above
    private static final String SHA_256_VALUE = "62cadeec039703ff336d692a6ba7f1690639cebef44d38fa203b03e195b9ad55";

    static {
        URL url = Objects.requireNonNull(ChecksumRuleTest.class.getResource("/mock-artifact.txt"));
        mockArtifact = new File(url.getPath());
    }

    /**
     * Tests any IO exception during the computation of the checksum.
     * <p>
     *     {@code FileNotFoundException} is the easiest to trigger, but can not be triggered from the {@link ChecksumRule#execute} method.
     * </p>
     */
    @Test
    void validateChecksum_errorHandling() {
        assertThat(ChecksumRule.validateChecksum(ChecksumAlgorithm.MD5, "abcdef", nonExistentArtifact))
                .contains("FileNotFoundException");
    }

    static Stream<Arguments> execute_works() {
        return Stream.of(
                // No checksums, no errors, even if the file does not exist
                Arguments.of(createMockBillOfMaterials(Map.of(), nonExistentArtifact), null),
                // Artifact file is `null`
                Arguments.of(
                        createMockBillOfMaterials(Map.of(ChecksumAlgorithm.SHA_256, SHA_256_VALUE), null),
                        "Missing file"),
                // Artifact file is missing
                Arguments.of(
                        createMockBillOfMaterials(
                                Map.of(ChecksumAlgorithm.SHA_256, SHA_256_VALUE), nonExistentArtifact),
                        "Missing file"),
                // Unsupported algorithm: the JRE does not support BLAKE yet
                Arguments.of(
                        createMockBillOfMaterials(Map.of(ChecksumAlgorithm.BLAKE3, "abcdef"), mockArtifact),
                        "BLAKE3-256 is not supported"),
                // Existing file with wrong checksum
                Arguments.of(
                        createMockBillOfMaterials(Map.of(ChecksumAlgorithm.SHA_256, "abcdef"), mockArtifact),
                        "Invalid SHA_256 checksum"),
                // Existing file with correct checksum
                Arguments.of(
                        createMockBillOfMaterials(Map.of(ChecksumAlgorithm.SHA_256, SHA_256_VALUE), mockArtifact),
                        null));
    }

    @ParameterizedTest
    @MethodSource
    void execute_works(BillOfMaterials bom, @Nullable String errorMessage) {
        ChecksumRule rule = new ChecksumRule();
        if (errorMessage != null) {
            assertThatThrownBy(() -> rule.execute(bom))
                    .isInstanceOf(MojoFailureException.class)
                    .hasMessageContaining(errorMessage);
        } else {
            assertDoesNotThrow(() -> rule.execute(bom));
        }
    }

    private static BillOfMaterials createMockBillOfMaterials(
            Map<ChecksumAlgorithm, String> dependencyChecksums, @Nullable File dependencyFile) {
        DefaultBillOfMaterials.Builder builder = DefaultBillOfMaterials.newBuilder()
                .setBillOfMaterials(new DefaultArtifact("groupId:artifactId:xml:cyclonedx:1.0.0"));
        Component validComponent = createComponent(Map.of(ChecksumAlgorithm.SHA_256, SHA_256_VALUE), mockArtifact);
        return builder.setComponent(validComponent)
                .addDependency(createComponent(dependencyChecksums, dependencyFile))
                .get();
    }

    private static Component createComponent(Map<ChecksumAlgorithm, String> checksums, @Nullable File file) {
        DefaultComponent.Builder builder = DefaultComponent.newBuilder()
                .setArtifact(new DefaultArtifact("groupId", "artifactId", null, "jar", "1.0.0", null, file));
        checksums.forEach(builder::addChecksum);
        return builder.get();
    }
}
