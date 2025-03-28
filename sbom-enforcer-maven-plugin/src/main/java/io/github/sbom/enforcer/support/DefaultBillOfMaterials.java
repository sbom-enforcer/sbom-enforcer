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

import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.Component;
import io.github.sbom.enforcer.internal.Artifacts;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;
import org.eclipse.aether.artifact.Artifact;
import org.jspecify.annotations.Nullable;

/**
 * Default {@link BillOfMaterials} implementation.
 */
public class DefaultBillOfMaterials implements BillOfMaterials {

    private final Artifact billOfMaterials;
    private final Component component;
    private final Set<Component> dependencies;

    public static Builder newBuilder() {
        return new Builder();
    }

    private DefaultBillOfMaterials(Artifact billOfMaterials, Component component, Set<Component> dependencies) {
        this.billOfMaterials = billOfMaterials;
        this.component = component;
        this.dependencies = Collections.unmodifiableSet(dependencies);
    }

    @Override
    public Artifact getBillOfMaterials() {
        return billOfMaterials;
    }

    @Override
    public Component getComponent() {
        return component;
    }

    @Override
    public Collection<? extends Component> getDependencies() {
        return dependencies;
    }

    public static final class Builder implements Supplier<BillOfMaterials> {
        private @Nullable Artifact billOfMaterials;
        private @Nullable Component component;
        private final Set<Component> dependencies =
                new TreeSet<>((left, right) -> Artifacts.compare(left.getArtifact(), right.getArtifact()));

        public Builder() {}

        public Builder setBillOfMaterials(Artifact billOfMaterials) {
            this.billOfMaterials = billOfMaterials;
            return this;
        }

        public Builder setComponent(Component component) {
            this.component = component;
            return this;
        }

        public Builder addDependency(Component component) {
            dependencies.add(component);
            return this;
        }

        @Override
        public BillOfMaterials get() {
            if (billOfMaterials == null) {
                throw new IllegalStateException("No SBOM has been specified");
            }
            if (component == null) {
                throw new IllegalStateException("No component has been specified");
            }
            return new DefaultBillOfMaterials(billOfMaterials, component, dependencies);
        }
    }
}
