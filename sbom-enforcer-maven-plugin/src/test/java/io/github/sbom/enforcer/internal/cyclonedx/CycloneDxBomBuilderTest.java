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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.BomBuilderRequest;
import io.github.sbom.enforcer.Component;
import io.github.sbom.enforcer.support.DefaultBomBuilderRequest;
import io.github.sbom.enforcer.support.DefaultExternalReference;
import java.io.File;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Objects;
import org.codehaus.plexus.ContainerConfiguration;
import org.codehaus.plexus.DefaultContainerConfiguration;
import org.codehaus.plexus.DefaultPlexusContainer;
import org.codehaus.plexus.PlexusConstants;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.PlexusContainerException;
import org.codehaus.plexus.classworlds.ClassWorld;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.LocalRepositoryManager;
import org.eclipse.aether.spi.localrepo.LocalRepositoryManagerFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CycloneDxBomBuilderTest {

    private static final PackageURL log4jCorePurl =
            createPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.24.3?type=jar");
    private static final PackageURL log4jApiPurl =
            createPurl("pkg:maven/org.apache.logging.log4j/log4j-api@2.24.3?type=jar");

    @TempDir
    private static Path localRepositoryPath;

    private static PlexusContainer container;
    private static RepositorySystem repoSystem;
    private static RepositorySystemSession repoSession;

    private static PackageURL createPurl(String purl) {
        try {
            return new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            throw new AssertionError(e);
        }
    }

    private static ContainerConfiguration setupContainerConfiguration() {
        ClassWorld classWorld =
                new ClassWorld("plexus.core", Thread.currentThread().getContextClassLoader());
        return new DefaultContainerConfiguration()
                .setClassWorld(classWorld)
                .setClassPathScanning(PlexusConstants.SCANNING_INDEX)
                .setAutoWiring(true)
                .setName("maven");
    }

    private static PlexusContainer setupContainer() throws PlexusContainerException {
        return new DefaultPlexusContainer(setupContainerConfiguration());
    }

    @BeforeAll
    static void setup() throws Exception {
        container = setupContainer();
        repoSystem = container.lookup(RepositorySystem.class);
        LocalRepositoryManagerFactory factory = container.lookup(LocalRepositoryManagerFactory.class, "simple");
        DefaultRepositorySystemSession repoSession = new DefaultRepositorySystemSession();
        LocalRepositoryManager manager =
                factory.newInstance(repoSession, new LocalRepository(localRepositoryPath.toFile()));
        repoSession.setLocalRepositoryManager(manager);
        CycloneDxBomBuilderTest.repoSession = repoSession;
    }

    @Test
    void testCreateBom() throws Exception {
        CycloneDxBomBuilder builder = new CycloneDxBomBuilder(repoSystem);
        Artifact artifact = new DefaultArtifact("org.apache.logging.log4j", "log4j-core", null, "jar", "2.24.3");
        File bomFile =
                new File(Objects.requireNonNull(CycloneDxBomBuilderTest.class.getResource("/simple-cyclonedx.xml"))
                        .toURI());
        Artifact bomArtifact = withExtension(withClassifier(artifact, "cyclonedx"), "xml");
        bomArtifact = bomArtifact.setFile(bomFile);

        BomBuilderRequest request = DefaultBomBuilderRequest.newBuilder()
                .setArtifact(artifact)
                .setMainBillOfMaterials(bomArtifact)
                .get();

        BillOfMaterials bom = builder.build(repoSession, request);
        assertThat(bom).isNotNull();
        // Main component
        Component component = bom.getComponent();
        assertThat(component).isNotNull();
        assertThat(component.getPurl()).isEqualTo(log4jCorePurl);
        assertThat(component.getArtifact()).isEqualTo(artifact);
        assertThat(component.getBillsOfMaterials()).hasSize(1).containsExactly(bomArtifact);
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
        assertThat(dependency.getPurl()).isEqualTo(log4jApiPurl);
        assertThat(dependency.getArtifact()).isNotNull();
        assertThat(dependency.getBillsOfMaterials()).hasSize(1);
        assertThat(dependency.getChecksums())
                .hasSize(2)
                .containsEntry(Component.ChecksumAlgorithm.MD5, "d89516699543c5c21be87ee1760695f3")
                .containsEntry(Component.ChecksumAlgorithm.SHA1, "b02c125db8b6d295adf72ae6e71af5d83bce2370");
        assertThat(dependency.getExternalReferences()).isEmpty();
    }
}
