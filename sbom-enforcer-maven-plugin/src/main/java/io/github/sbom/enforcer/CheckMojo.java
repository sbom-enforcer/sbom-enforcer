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

import io.github.sbom.enforcer.internal.Artifacts;
import io.github.sbom.enforcer.internal.BomUtils;
import javax.inject.Inject;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.AbstractForwardingRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.repository.WorkspaceReader;
import org.jspecify.annotations.Nullable;

@Mojo(name = "check", defaultPhase = LifecyclePhase.VERIFY)
public class CheckMojo extends AbstractMojo {

    /**
     * The current repository/network configuration of Maven.
     */
    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    private RepositorySystemSession repoSession;

    /**
     * The current Maven project.
     */
    private final MavenProject project;

    /**
     * Component used to retrieve artifacts from Maven repositories.
     */
    private final RepositorySystem repoSystem;

    @Inject
    public CheckMojo(MavenProject project, RepositorySystem repoSystem) {
        this.project = project;
        this.repoSystem = repoSystem;
    }

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        for (Artifact artifact : project.getAttachedArtifacts()) {
            if (BomUtils.isBomArtifact(Artifacts.toArtifact(artifact))) {
                checkBom(artifact);
            }
        }
    }

    private void checkBom(Artifact artifact) throws MojoExecutionException {}

    private static class NoCacheRepositorySystemSession extends AbstractForwardingRepositorySystemSession {

        private final RepositorySystemSession session;

        NoCacheRepositorySystemSession(RepositorySystemSession session) {
            this.session = session;
        }

        @Override
        protected RepositorySystemSession getSession() {
            return session;
        }

        @Override
        public String getChecksumPolicy() {
            return RepositoryPolicy.CHECKSUM_POLICY_FAIL;
        }

        @Override
        public String getUpdatePolicy() {
            return RepositoryPolicy.UPDATE_POLICY_ALWAYS;
        }

        @Override
        public @Nullable WorkspaceReader getWorkspaceReader() {
            return null;
        }
    }
}
