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

import java.util.Collection;
import org.eclipse.aether.artifact.Artifact;

/**
 * A simplified and format independent model of a Software Bill of Materials (SBOM).
 */
public interface BillOfMaterials {

    /**
     * Returns the artifact used to generate this object.
     */
    Artifact getBillOfMaterials();

    /**
     * Returns the component described by this bill of materials.
     */
    Component getComponent();

    /**
     * Returns the dependencies of the described component.
     */
    Collection<? extends Component> getDependencies();
}
