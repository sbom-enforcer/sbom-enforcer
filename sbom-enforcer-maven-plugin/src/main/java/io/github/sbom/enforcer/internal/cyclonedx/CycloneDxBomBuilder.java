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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.BomBuilder;
import io.github.sbom.enforcer.BomBuilderRequest;
import io.github.sbom.enforcer.BomBuildingException;
import io.github.sbom.enforcer.Component;
import io.github.sbom.enforcer.Component.ChecksumAlgorithm;
import io.github.sbom.enforcer.internal.Artifacts;
import io.github.sbom.enforcer.support.DefaultBillOfMaterials;
import io.github.sbom.enforcer.support.DefaultComponent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Metadata;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactResolutionException;

/**
 * Creates a {@link BillOfMaterials} model for a CycloneDX document.
 */
@Named("cyclonedx")
@Singleton
@org.codehaus.plexus.component.annotations.Component(role = BomBuilder.class, hint = "cyclonedx")
public class CycloneDxBomBuilder implements BomBuilder {

    private final RepositorySystem repoSystem;

    @Inject
    public CycloneDxBomBuilder(RepositorySystem repoSystem) {
        this.repoSystem = repoSystem;
    }

    @Override
    public boolean isSupported(Artifact billOfMaterials) {
        return "cyclonedx".equals(billOfMaterials.getClassifier());
    }

    @Override
    public BillOfMaterials build(RepositorySystemSession repoSession, BomBuilderRequest request)
            throws BomBuildingException {
        Bom bom = CycloneDxUtils.parseArtifact(request.getMainBillOfMaterials());
        org.cyclonedx.model.Component cdxComponent = getMainComponent(request, bom);
        Component mainComponent =
                processMainComponent(cdxComponent, request.getArtifact(), request.getAllBillsOfMaterials());
        DefaultBillOfMaterials.Builder builder =
                DefaultBillOfMaterials.newBuilder().setComponent(mainComponent);
        // Create dependencies
        for (org.cyclonedx.model.Component dependency : bom.getComponents()) {
            builder.addDependency(createDependency(repoSession, dependency));
        }
        return builder.get();
    }

    private static org.cyclonedx.model.Component getMainComponent(BomBuilderRequest request, Bom bom)
            throws BomBuildingException {
        Metadata metadata = bom.getMetadata();
        if (metadata == null) {
            throw new BomBuildingException(
                    "BOM artifact " + request.getMainBillOfMaterials() + " does not contain a `$.metadata` element.");
        }
        org.cyclonedx.model.Component cdxComponent = metadata.getComponent();
        if (cdxComponent == null) {
            throw new BomBuildingException("BOM artifact " + request.getMainBillOfMaterials()
                    + " does not contain a `$.metadata.component` element.");
        }
        return cdxComponent;
    }

    private Component processMainComponent(
            org.cyclonedx.model.Component component, Artifact artifact, Collection<Artifact> allBillsOfMaterials)
            throws BomBuildingException {
        DefaultComponent.Builder builder = DefaultComponent.newBuilder().setArtifact(artifact);
        allBillsOfMaterials.forEach(builder::addBillOfMaterials);
        processGenericComponent(builder, component);
        return builder.get();
    }

    private Component createDependency(RepositorySystemSession repoSession, org.cyclonedx.model.Component cdxComponent)
            throws BomBuildingException {
        Artifact artifact = CycloneDxUtils.toArtifact(cdxComponent);
        RemoteRepository remoteRepository = Artifacts.getRemoteRepository(artifact);
        try {
            artifact = Artifacts.downloadArtifact(repoSystem, repoSession, artifact, remoteRepository);
        } catch (ArtifactResolutionException e) {
            throw new BomBuildingException("Failed to download artifact " + artifact, e);
        }
        DefaultComponent.Builder builder = DefaultComponent.newBuilder().setArtifact(artifact);
        processGenericComponent(builder, cdxComponent);
        for (Artifact bom : findBomArtifacts(repoSession, artifact, remoteRepository)) {
            builder.addBillOfMaterials(bom);
        }
        return builder.get();
    }

    private Collection<Artifact> findBomArtifacts(
            RepositorySystemSession repoSession, Artifact artifact, RemoteRepository remoteRepository) {
        Collection<Artifact> bomArtifacts = new ArrayList<>();
        Artifact cycloneDxArtifact =
                Artifacts.withClassifier(artifact.setFile(null), CycloneDxUtils.CYCLONE_DX_CLASSIFIER);
        for (String extension : new String[] {"xml", "json"}) {
            try {
                Artifact bom = Artifacts.downloadArtifact(
                        repoSystem,
                        repoSession,
                        Artifacts.withExtension(cycloneDxArtifact, extension),
                        remoteRepository);
                bomArtifacts.add(bom);
            } catch (ArtifactResolutionException e) {
                // The artifact is not present
            }
        }
        return bomArtifacts;
    }

    private static void processGenericComponent(
            DefaultComponent.Builder builder, org.cyclonedx.model.Component component) throws BomBuildingException {
        String purl = component.getPurl();
        try {
            builder.setPurl(new PackageURL(purl));
        } catch (MalformedPackageURLException e) {
            throw new BomBuildingException("Unable to parse invalid pURL: " + purl);
        }
        List<Hash> hashes = component.getHashes();
        if (hashes != null) {
            for (Hash hash : hashes) {
                builder.addChecksum(ChecksumAlgorithm.fromCycloneDx(hash.getAlgorithm()), hash.getValue());
            }
        }
        List<ExternalReference> externalReferences = component.getExternalReferences();
        if (externalReferences != null) {
            for (ExternalReference externalReference : externalReferences) {
                builder.addExternalReference(externalReference.getType().getTypeName(), externalReference.getUrl());
            }
        }
    }
}
