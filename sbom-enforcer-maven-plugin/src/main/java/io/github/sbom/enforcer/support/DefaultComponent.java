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
package io.github.sbom.enforcer.support;

import com.github.packageurl.PackageURL;
import io.github.sbom.enforcer.Component;
import io.github.sbom.enforcer.internal.Artifacts;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.eclipse.aether.artifact.Artifact;
import org.jspecify.annotations.Nullable;

/**
 * Default {@link Component} implementation.
 */
public final class DefaultComponent implements Component {

    private final Artifact artifact;
    private final @Nullable PackageURL purl;
    private final Set<Artifact> billsOfMaterials;
    private final Set<ExternalReference> externalReferences;
    private final Map<ChecksumAlgorithm, String> checksums;

    public static Builder newBuilder() {
        return new Builder();
    }

    private DefaultComponent(
            Artifact artifact,
            @Nullable PackageURL purl,
            Set<Artifact> billsOfMaterials,
            Set<ExternalReference> externalReferences,
            Map<ChecksumAlgorithm, String> checksums) {
        this.artifact = artifact;
        this.purl = purl;
        this.billsOfMaterials = Collections.unmodifiableSet(billsOfMaterials);
        this.externalReferences = Collections.unmodifiableSet(externalReferences);
        this.checksums = Collections.unmodifiableMap(checksums);
    }

    @Override
    public Artifact getArtifact() {
        return artifact;
    }

    @Override
    public @Nullable PackageURL getPurl() {
        return purl;
    }

    @Override
    public Collection<Artifact> getBillsOfMaterials() {
        return billsOfMaterials;
    }

    @Override
    public Collection<ExternalReference> getExternalReferences() {
        return externalReferences;
    }

    @Override
    public Map<ChecksumAlgorithm, String> getChecksums() {
        return checksums;
    }

    public static final class Builder {
        private @Nullable Artifact artifact;
        private @Nullable PackageURL purl;
        private final Set<Artifact> billsOfMaterials = new TreeSet<>(Artifacts::compare);
        private final Set<ExternalReference> externalReferences = new TreeSet<>(DefaultExternalReference::compare);
        private final Map<ChecksumAlgorithm, String> checksums = new EnumMap<>(ChecksumAlgorithm.class);

        private Builder() {}

        public Builder setArtifact(Artifact artifact) {
            this.artifact = artifact;
            return this;
        }

        public Builder setPurl(PackageURL purl) {
            this.purl = purl;
            return this;
        }

        public Builder addBillOfMaterials(Artifact artifact) {
            this.billsOfMaterials.add(artifact);
            return this;
        }

        public Builder addExternalReference(String referenceType, String location) {
            this.externalReferences.add(DefaultExternalReference.of(referenceType, location));
            return this;
        }

        public Builder addChecksum(ChecksumAlgorithm checksumAlgorithm, String value) {
            this.checksums.put(checksumAlgorithm, value);
            return this;
        }

        public Component get() {
            if (artifact == null) {
                throw new IllegalStateException("Required artifact object was not provided.");
            }
            return new DefaultComponent(artifact, purl, billsOfMaterials, externalReferences, checksums);
        }
    }
}
