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

import static io.github.sbom.enforcer.internal.Artifacts.withClassifier;
import static io.github.sbom.enforcer.internal.Artifacts.withExtension;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.BomBuilderRequest;
import io.github.sbom.enforcer.BomBuildingException;
import io.github.sbom.enforcer.Component;
import io.github.sbom.enforcer.internal.CollectionUtils;
import io.github.sbom.enforcer.internal.MojoUtils;
import io.github.sbom.enforcer.support.DefaultBomBuilderRequest;
import io.github.sbom.enforcer.support.DefaultComponent;
import io.github.sbom.enforcer.support.DefaultExternalReference;
import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.logging.Logger;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.ArtifactProperties;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CycloneDxBomBuilderTest {

    private static final PackageURL log4jCorePurl = createPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.24.3");
    private static final PackageURL log4jApiPurl = createPurl("pkg:maven/org.apache.logging.log4j/log4j-api@2.24.3");
    private static final PackageURL log4jApiRedhatPurl = createPurl(
            "pkg:maven/org.apache.logging.log4j/log4j-api@2.23.1.redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga");
    private static final PackageURL minimalPurl = createPurl("pkg:maven/groupId/artifactId");

    @TempDir
    private static Path localRepositoryPath;

    private static RepositorySystem repoSystem;
    private static RepositorySystemSession repoSession;

    private static PackageURL createPurl(String purl) {
        try {
            return new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            throw new AssertionError(e);
        }
    }

    @BeforeAll
    static void setup() throws Exception {
        PlexusContainer container = MojoUtils.setupContainer();
        repoSystem = container.lookup(RepositorySystem.class);
        repoSession = MojoUtils.createRepositorySystemSession(container, localRepositoryPath);
    }

    static Stream<Arguments> createSingleDepBom() {
        return Stream.of(
                Arguments.of("single-dep-cyclonedx.xml", log4jApiPurl, 1),
                // RedHat does not publish SBOMs
                Arguments.of("single-dep2-cyclonedx.xml", log4jApiRedhatPurl, 0));
    }

    @ParameterizedTest
    @MethodSource
    void createSingleDepBom(String resource, PackageURL dependencyPurl, int bomCount) throws Exception {
        CycloneDxBomBuilder builder = new CycloneDxBomBuilder(repoSystem, mock(Logger.class));
        BomBuilderRequest request = createRequest(resource);
        BillOfMaterials bom = builder.build(repoSession, request);
        assertThat(bom).isNotNull();
        // Main component
        Component component = bom.getComponent();
        assertThat(component).isNotNull();
        assertThat(component.getPurl()).isEqualTo(log4jCorePurl);
        assertArtifactEquals(request.getArtifact(), component.getArtifact());
        assertThat(component.getBillsOfMaterials()).hasSize(1).containsExactly(request.getMainBillOfMaterials());
        assertThat(component.getChecksums()).isEmpty();
        assertThat(component.getExternalReferences())
                .hasSize(1)
                .contains(DefaultExternalReference.of(
                        "vulnerability-assertion", "https://logging.apache.org/cyclonedx/vdr.xml"));
        // Dependencies
        Collection<? extends Component> dependencies = bom.getDependencies();
        assertThat(dependencies).hasSize(1);
        Component dependency = dependencies.iterator().next();
        assertThat(dependency).isNotNull();
        assertThat(dependency.getPurl()).isEqualTo(dependencyPurl);
        assertThat(dependency.getArtifact()).isNotNull();
        assertThat(dependency.getArtifact().getFile()).exists();
        assertThat(dependency.getBillsOfMaterials()).hasSize(bomCount);
        assertThat(dependency.getChecksums())
                .hasSize(2)
                .containsEntry(Component.ChecksumAlgorithm.MD5, "d89516699543c5c21be87ee1760695f3")
                .containsEntry(Component.ChecksumAlgorithm.SHA1, "b02c125db8b6d295adf72ae6e71af5d83bce2370");
        assertThat(dependency.getExternalReferences()).isEmpty();
    }

    @Test
    void createNonExistentDepBom() throws Exception {
        CycloneDxBomBuilder builder = new CycloneDxBomBuilder(repoSystem, mock(Logger.class));
        BomBuilderRequest request = createRequest("non-existent-dep-cyclonedx.xml");
        BillOfMaterials bom = builder.build(repoSession, request);
        assertThat(bom).isNotNull();
        // Dependencies
        Collection<? extends Component> dependencies = bom.getDependencies();
        assertThat(dependencies).hasSize(1);
        Component dependency = dependencies.iterator().next();
        assertThat(dependency).isNotNull();
        assertThat(dependency.getPurl()).isEqualTo(new PackageURL("pkg:maven/invalid/artifactId@1.0.0"));
        Artifact dependencyArtifact = dependency.getArtifact();
        assertThat(dependencyArtifact).isNotNull();
        assertThat(dependencyArtifact.getFile()).isNull();
        assertThat(dependency.getBillsOfMaterials()).isEmpty();
        assertThat(dependency.getChecksums()).isEmpty();
        assertThat(dependency.getExternalReferences()).isEmpty();
    }

    @Test
    void createNoDepBom() throws Exception {
        CycloneDxBomBuilder builder = new CycloneDxBomBuilder(repoSystem, mock(Logger.class));
        BomBuilderRequest request = createRequest("no-dep-cyclonedx.xml");
        BillOfMaterials bom = builder.build(repoSession, request);
        assertThat(bom).isNotNull();
        // Main component
        Component component = bom.getComponent();
        assertThat(component).isNotNull();
        assertThat(component.getPurl()).isEqualTo(log4jCorePurl);
        assertArtifactEquals(request.getArtifact(), component.getArtifact());
        assertThat(component.getBillsOfMaterials()).hasSize(1).containsExactly(request.getMainBillOfMaterials());
        assertThat(component.getChecksums()).isEmpty();
        assertThat(component.getExternalReferences()).isEmpty();
    }

    static Stream<String> createEmptyBom() {
        return Stream.of("empty-cyclonedx.xml", "empty2-cyclonedx.xml");
    }

    @ParameterizedTest
    @MethodSource
    void createEmptyBom(String resource) throws Exception {
        CycloneDxBomBuilder builder = new CycloneDxBomBuilder(repoSystem, mock(Logger.class));
        BomBuilderRequest request = createRequest(resource);
        assertThatThrownBy(() -> builder.build(repoSession, request)).isInstanceOf(BomBuildingException.class);
    }

    static Stream<Arguments> processValidComponent() throws MalformedPackageURLException {
        org.cyclonedx.model.Component withPurl = new org.cyclonedx.model.Component();
        withPurl.setName("log4j-api");
        withPurl.setPurl(log4jApiPurl);
        org.cyclonedx.model.Component withoutPurl = new org.cyclonedx.model.Component();
        withoutPurl.setGroup("org.apache.logging.log4j");
        withoutPurl.setName("log4j-api");
        withoutPurl.setVersion("2.24.3");
        org.cyclonedx.model.Component withoutVersion = new org.cyclonedx.model.Component();
        withoutVersion.setGroup("org.apache.logging.log4j");
        withoutVersion.setName("log4j-api");

        Component log4jApi = DefaultComponent.newBuilder()
                .setPurl(log4jApiPurl)
                .setArtifact(createArtifact(minimalPurl))
                .get();
        Component versionLessLog4jApi = DefaultComponent.newBuilder()
                .setPurl(new PackageURL("pkg:maven/org.apache.logging.log4j/log4j-api"))
                .setArtifact(createArtifact(minimalPurl))
                .get();
        return Stream.of(
                Arguments.of(log4jApi, withPurl),
                Arguments.of(log4jApi, withoutPurl),
                Arguments.of(versionLessLog4jApi, withoutVersion));
    }

    @ParameterizedTest
    @MethodSource
    void processValidComponent(Component expectedOutput, org.cyclonedx.model.Component input)
            throws BomBuildingException {
        DefaultComponent.Builder builder = DefaultComponent.newBuilder().setArtifact(createArtifact(minimalPurl));
        CycloneDxBomBuilder.processGenericComponent(builder, input);
        assertThat(builder.get()).isEqualTo(expectedOutput);
    }

    private static Artifact createArtifact(PackageURL purl) {
        Map<String, String> qualifiers = CollectionUtils.nullToEmpty(purl.getQualifiers());
        String type = qualifiers.getOrDefault(ArtifactProperties.TYPE, "jar");
        return new DefaultArtifact(purl.getNamespace(), purl.getName(), null, type, purl.getVersion());
    }

    private static BomBuilderRequest createRequest(String bomResource) throws URISyntaxException {
        Artifact artifact = createArtifact(log4jCorePurl);
        File bomFile = new File(Objects.requireNonNull(CycloneDxBomBuilderTest.class.getResource("/" + bomResource))
                .toURI());
        Artifact bomArtifact = withExtension(withClassifier(artifact, "cyclonedx"), "xml");
        bomArtifact = bomArtifact.setFile(bomFile);

        return DefaultBomBuilderRequest.newBuilder()
                .setArtifact(artifact)
                .setMainBillOfMaterials(bomArtifact)
                .get();
    }

    private static void assertArtifactEquals(Artifact expected, Artifact actual) {
        assertThat(actual.getGroupId()).as("groupId of %s", actual).isEqualTo(expected.getGroupId());
        assertThat(actual.getArtifactId()).as("artifactId of %s", actual).isEqualTo(expected.getArtifactId());
        assertThat(actual.getClassifier()).as("classifier of %s", actual).isEqualTo(expected.getClassifier());
        assertThat(actual.getExtension()).as("extension of %s", actual).isEqualTo(expected.getExtension());
        assertThat(actual.getVersion()).as("version of %s", actual).isEqualTo(expected.getVersion());
    }
}
