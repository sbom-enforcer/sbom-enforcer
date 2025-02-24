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

import io.github.sbom.enforcer.BomBuilderRequest;
import io.github.sbom.enforcer.internal.Artifacts;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;
import org.eclipse.aether.artifact.Artifact;
import org.jspecify.annotations.Nullable;

/**
 * Default {@link BomBuilderRequest} implementation.
 */
public class DefaultBomBuilderRequest implements BomBuilderRequest {

    private final Artifact artifact;
    private final Artifact mainBillOfMaterials;
    private final Set<Artifact> allBillsOfMaterials;

    public static Builder newBuilder() {
        return new Builder();
    }

    private DefaultBomBuilderRequest(
            Artifact artifact, Artifact mainBillOfMaterials, Set<Artifact> allBillsOfMaterials) {
        this.artifact = artifact;
        this.mainBillOfMaterials = mainBillOfMaterials;
        this.allBillsOfMaterials = Collections.unmodifiableSet(allBillsOfMaterials);
    }

    @Override
    public Artifact getArtifact() {
        return artifact;
    }

    @Override
    public Artifact getMainBillOfMaterials() {
        return mainBillOfMaterials;
    }

    @Override
    public Collection<Artifact> getAllBillsOfMaterials() {
        return allBillsOfMaterials;
    }

    public static final class Builder implements Supplier<BomBuilderRequest> {
        private @Nullable Artifact artifact;
        private @Nullable Artifact mainBillOfMaterials;
        private final Set<Artifact> allBillsOfMaterials = new TreeSet<>(Artifacts::compare);

        private Builder() {}

        public Builder setArtifact(Artifact artifact) {
            this.artifact = artifact;
            return this;
        }

        public Builder setMainBillOfMaterials(Artifact mainBillOfMaterials) {
            this.mainBillOfMaterials = mainBillOfMaterials;
            return addBillOfMaterials(mainBillOfMaterials);
        }

        public Builder addBillOfMaterials(Artifact billOfMaterials) {
            this.allBillsOfMaterials.add(billOfMaterials);
            return this;
        }

        @Override
        public BomBuilderRequest get() {
            if (artifact == null || mainBillOfMaterials == null) {
                throw new IllegalStateException("Required `artifact` (" + artifact + ") and `mainBillOfMaterials` ("
                        + mainBillOfMaterials + ") arguments were not provided.");
            }
            return new DefaultBomBuilderRequest(artifact, mainBillOfMaterials, allBillsOfMaterials);
        }
    }
}
