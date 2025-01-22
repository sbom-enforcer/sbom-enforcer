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
package io.github.sbom.enforcer.internal;

import io.github.sbom.enforcer.Component;
import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.ArtifactProperties;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

/**
 * Utilities for {@link Artifact} objects.
 */
public final class Artifacts {

    public static Artifact toArtifact(org.apache.maven.artifact.Artifact mavenArtifact) {
        Objects.requireNonNull(mavenArtifact);
        String version = mavenArtifact.getVersion() != null
                ? mavenArtifact.getVersion()
                : mavenArtifact.getVersionRange().toString();
        Map<String, String> properties = new HashMap<>();
        // Add important properties
        properties.put(ArtifactProperties.TYPE, mavenArtifact.getType());
        ArtifactRepository repository = mavenArtifact.getRepository();
        if (repository != null) {
            String repositoryUrl = repository.getUrl();
            if (repositoryUrl != null) {
                properties.put(Component.Properties.REPOSITORY_URL, repositoryUrl);
            }
        }

        Artifact aetherArtifact = new DefaultArtifact(
                mavenArtifact.getGroupId(),
                mavenArtifact.getArtifactId(),
                mavenArtifact.getClassifier(),
                mavenArtifact.getArtifactHandler().getExtension(),
                version,
                Collections.unmodifiableMap(properties),
                (File) null);
        aetherArtifact = aetherArtifact.setFile(mavenArtifact.getFile());

        return aetherArtifact;
    }

    public static Artifact withClassifier(Artifact artifact, String classifier) {
        return new DefaultArtifact(
                artifact.getGroupId(),
                artifact.getArtifactId(),
                classifier,
                artifact.getExtension(),
                artifact.getVersion(),
                Map.copyOf(artifact.getProperties()),
                artifact.getFile());
    }

    public static Artifact withExtension(Artifact artifact, String extension) {
        return new DefaultArtifact(
                artifact.getGroupId(),
                artifact.getArtifactId(),
                artifact.getClassifier(),
                extension,
                artifact.getVersion(),
                Map.copyOf(artifact.getProperties()),
                artifact.getFile());
    }

    public static RemoteRepository getRemoteRepository(Artifact artifact) {
        String repositoryUrl =
                artifact.getProperty(Component.Properties.REPOSITORY_URL, Component.Properties.MAVEN_CENTRAL_URL);
        return new RemoteRepository.Builder(null, "default", repositoryUrl).build();
    }

    public static Artifact downloadArtifact(
            RepositorySystem repoSystem,
            RepositorySystemSession repoSession,
            Artifact artifact,
            RemoteRepository remoteRepository)
            throws ArtifactResolutionException {
        ArtifactRequest request = new ArtifactRequest();
        request.setArtifact(artifact);
        request.setRepositories(Collections.singletonList(remoteRepository));

        ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
        return result.getArtifact();
    }

    public static int compare(Artifact left, Artifact right) {
        int result = left.getGroupId().compareTo(right.getGroupId());
        if (result == 0) {
            result = left.getArtifactId().compareTo(right.getArtifactId());
        }
        if (result == 0) {
            result = left.getVersion().compareTo(right.getVersion());
        }
        if (result == 0) {
            result = left.getClassifier().compareTo(right.getClassifier());
        }
        if (result == 0) {
            result = left.getExtension().compareTo(right.getExtension());
        }
        return result;
    }

    private Artifacts() {}
}
