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
package io.github.sbom.enforcer;

import com.github.packageurl.PackageURL;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import org.eclipse.aether.artifact.Artifact;
import org.jspecify.annotations.Nullable;

/**
 * Metadata associated to a Maven artifact.
 */
public interface Component {

    /**
     * The resolved artifact described by this component.
     */
    Artifact getArtifact();

    /**
     * The package URL of the described component as specified in the bill of materials.
     */
    @Nullable
    PackageURL getPurl();

    /**
     * All the SBOM artifacts published for the given component.
     */
    Collection<Artifact> getBillsOfMaterials();

    /**
     * References to other documents related to the artifact as specified in the bill of materials.
     */
    Collection<ExternalReference> getExternalReferences();

    /**
     * Hash values of the component as specified in the bill of materials
     * <p>
     *     These can differ from the hashes of the file given by {@link #getArtifact()}.
     * </p>
     * @return A map from hash algorithm names to hash values.
     */
    Map<ChecksumAlgorithm, String> getChecksums();

    /**
     * A reference to an external resource.
     */
    interface ExternalReference {

        /**
         * The type of external reference.
         * <p>
         *     The values can be any constants used by CycloneDX or SPDX.
         * </p>
         *
         * @see <a href="https://cyclonedx.org/docs/1.6/json/#components_items_externalReferences_items_type">CycloneDX external reference types</a>
         * @see <a href="https://spdx.github.io/spdx-spec/v2.3/external-repository-identifiers/">SPDX 2.x external repository identifiers</a>
         * @see <a href="https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Vocabularies/ExternalRefType/">SPDX 3.x external reference types</a>
         */
        String getReferenceType();

        /**
         * The location of the external resource.
         */
        String getLocation();

        /**
         * The MIME type of the external resource or {@code null} if unknown.
         */
        @Nullable
        String getContentType();
    }

    /**
     * Enumeration of supported checksum algorithms.
     */
    enum ChecksumAlgorithm {
        ADLER32(null, "ADLER32"),
        MD2(null, "MD2"),
        MD4(null, "MD4"),
        MD5("MD5", "MD5"),
        MD6(null, "MD6"),
        SHA1("SHA-1", "SHA1"),
        SHA224(null, "SHA224"),
        SHA_256("SHA-256", "SHA256"),
        SHA_384("SHA-384", "SHA384"),
        SHA_512("SHA-512", "SHA512"),
        SHA3_256("SHA3-256", "SHA3-256"),
        SHA3_512("SHA3-512", "SHA3-512"),
        SHA3_384("SHA3-384", "SHA3-384"),
        BLAKE2b_256("BLAKE2b-256", "BLAKE2b-256"),
        BLAKE2b_384("BLAKE2b-384", "BLAKE2b-384"),
        BLAKE2b_512("BLAKE2b-512", "BLAKE2b-512"),
        BLAKE3("BLAKE3", "BLAKE3");

        private final @Nullable String cyclonedx;
        private final @Nullable String spdx;

        ChecksumAlgorithm(@Nullable String cyclonedx, @Nullable String spdx) {
            this.cyclonedx = cyclonedx;
            this.spdx = spdx;
        }

        /**
         * Checks if the algorithm is supported by CycloneDX.
         * @return {@code true} if the algorithm is supported by the CycloneDX standard.
         */
        public boolean isCycloneDx() {
            return cyclonedx != null;
        }

        /**
         * Returns the identifier used in CycloneDX documents.
         */
        public String toCycloneDx() {
            return Objects.requireNonNull(cyclonedx);
        }

        /**
         * Parses a CycloneDX checksum identifier.
         */
        public static ChecksumAlgorithm fromCycloneDx(String spec) {
            Objects.requireNonNull(spec);
            for (ChecksumAlgorithm algorithm : values()) {
                if (spec.equals(algorithm.cyclonedx)) {
                    return algorithm;
                }
            }
            throw new IllegalArgumentException("No enum constant with spec " + spec);
        }
    }

    /**
     * List of properties of {@link Artifact} objects returned by {@link Component} methods.
     */
    final class Properties {

        /**
         * The URL of the Maven repository where the component is or will be available.
         * <p>
         *     This property is always present if the component is not on Maven Central.
         * </p>
         */
        public static final String REPOSITORY_URL = "repository_url";

        /**
         * The URL of the Maven Central repository used in the Super POM.
         * @see <a href="https://maven.apache.org/ref/current/maven-model-builder/super-pom.html">Super POM</a>
         */
        public static final String MAVEN_CENTRAL_URL = "https://repo.maven.apache.org/maven2";

        /**
         * Alternative location of Maven Central.
         */
        public static final String MAVEN_CENTRAL_ALT_URL = "https://repo1.maven.org/maven2";

        private Properties() {}
    }
}
