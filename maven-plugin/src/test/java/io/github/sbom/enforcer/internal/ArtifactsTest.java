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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.stream.Stream;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ArtifactsTest {

    public static final String MAVEN_CENTRAL_URL = "https://repo.maven.apache.org/maven2";

    static Stream<Arguments> createRemoteRepository_propertyHandlesPolicies() {
        return Stream.of(
                Arguments.of(null, null),
                Arguments.of("", ""),
                Arguments.of(RepositoryPolicy.UPDATE_POLICY_ALWAYS, RepositoryPolicy.CHECKSUM_POLICY_FAIL));
    }

    @ParameterizedTest
    @MethodSource
    void createRemoteRepository_propertyHandlesPolicies(
            @Nullable String updatePolicy, @Nullable String checksumPolicy) {
        Artifact artifact = new DefaultArtifact("groupId:artifactId:1.0.0");
        RepositorySystemSession repoSession = mock(RepositorySystemSession.class);
        when(repoSession.getUpdatePolicy()).thenReturn(updatePolicy);
        when(repoSession.getChecksumPolicy()).thenReturn(checksumPolicy);

        RemoteRepository repo = Artifacts.getRemoteRepository(artifact, repoSession);
        for (boolean snapshot : new boolean[] {true, false}) {
            RepositoryPolicy policy = repo.getPolicy(snapshot);
            assertThat(policy.getUpdatePolicy()).isNotEmpty();
            assertThat(policy.getChecksumPolicy()).isNotEmpty();
        }
    }

    private static Stream<Arguments> createRemoteRepository_propertyHandlesRepositoryUrls() {
        return Stream.of(
                Arguments.of(null, MAVEN_CENTRAL_URL),
                Arguments.of(MAVEN_CENTRAL_URL, MAVEN_CENTRAL_URL),
                Arguments.of("https://repo1.maven.org/maven2", MAVEN_CENTRAL_URL),
                Arguments.of("https://example/maven2", "https://example/maven2"));
    }

    @ParameterizedTest
    @MethodSource
    void createRemoteRepository_propertyHandlesRepositoryUrls(@Nullable String inputUrl, String outputUrl) {
        Artifact artifact =
                new DefaultArtifact("groupId:artifactId:1.0.0", Collections.singletonMap("repository_url", inputUrl));
        RepositorySystemSession repoSession = mock(RepositorySystemSession.class);

        RemoteRepository repo = Artifacts.getRemoteRepository(artifact, repoSession);
        assertThat(repo.getUrl()).isEqualTo(outputUrl);
        if (MAVEN_CENTRAL_URL.equals(repo.getUrl())) {
            assertThat(repo.getId()).isEqualTo("central");
        }
    }
}
