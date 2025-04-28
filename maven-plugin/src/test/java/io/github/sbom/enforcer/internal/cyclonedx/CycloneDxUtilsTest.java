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
package io.github.sbom.enforcer.internal.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.packageurl.PackageURL;
import io.github.sbom.enforcer.BomBuildingException;
import java.util.stream.Stream;
import org.cyclonedx.model.Component;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class CycloneDxUtilsTest {

    static Stream<Arguments> toPackageURL_invalid() {
        Component invalidPurl = new Component();
        invalidPurl.setName("artifactId");
        invalidPurl.setPurl("invalid-purl");
        Component missingGroup = new Component();
        missingGroup.setName("artifactId");
        return Stream.of(
                Arguments.of(invalidPurl, "Invalid PURL"), Arguments.of(missingGroup, "Missing PURL and group"));
    }

    @ParameterizedTest
    @MethodSource
    void toPackageURL_invalid(Component component, String errorMessage) {
        assertThatThrownBy(() -> CycloneDxUtils.toPackageURL(component))
                .isInstanceOf(BomBuildingException.class)
                .hasMessageContaining(errorMessage);
    }

    static Stream<Component> toPackageURL_valid() {
        Component hasPurl = new Component();
        hasPurl.setName("artifactId");
        hasPurl.setPurl("pkg:maven/groupId/artifactId");
        Component hasGroup = new Component();
        hasGroup.setGroup("groupId");
        hasGroup.setName("artifactId");
        return Stream.of(hasPurl, hasGroup);
    }

    @ParameterizedTest
    @MethodSource
    void toPackageURL_valid(Component component) throws BomBuildingException {
        PackageURL purl = CycloneDxUtils.toPackageURL(component);
        assertThat(purl.canonicalize()).isEqualTo("pkg:maven/groupId/artifactId");
    }
}
