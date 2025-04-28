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
import io.github.sbom.enforcer.support.DefaultBomBuilderRequest;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.PluginParameterExpressionEvaluator;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.classworlds.realm.ClassRealm;
import org.codehaus.plexus.component.configurator.ComponentConfigurationException;
import org.codehaus.plexus.component.configurator.ComponentConfigurator;
import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluator;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.codehaus.plexus.configuration.DefaultPlexusConfiguration;
import org.codehaus.plexus.configuration.PlexusConfiguration;
import org.eclipse.aether.AbstractForwardingRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.LocalRepositoryManager;
import org.eclipse.aether.repository.NoLocalRepositoryManagerException;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.spi.localrepo.LocalRepositoryManagerFactory;

/**
 * Performs a configurable set of checks on the SBOMs attached to the build.
 * <p>
 *     See <a href="https://sbom-enforcer.github.io/maven-plugin/rules.html">Rules</a> for a list of available rules.
 * </p>
 */
@Mojo(name = "check", defaultPhase = LifecyclePhase.VERIFY)
public class CheckMojo extends AbstractMojo {

    /**
     * If set to {@code true}, the contents of the per-user local Maven repository are ignored
     * and a per-Maven module local Maven repository is used instead.
     */
    @Parameter(defaultValue = "false")
    private boolean usePrivateLocalRepo;

    /**
     * Configuration of the rules to execute.
     */
    @Parameter
    private PlexusConfiguration rules = new DefaultPlexusConfiguration("rules");

    /**
     * The current repository/network configuration of Maven.
     */
    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    private RepositorySystemSession repoSession;

    /**
     * Path to a local Maven repository to use if `usePrivateLocalRepo` is true.
     */
    @Parameter(defaultValue = "${project.build.directory}/sbom-enforcer/repository")
    protected Path privateLocalRepoPath;

    /**
     * The current Maven project.
     */
    private final MavenProject project;

    /**
     * The current Maven session
     */
    private final MavenSession session;

    /**
     * The mojoExecution of this mojo
     */
    private final MojoExecution mojoExecution;

    /**
     *
     */
    private final ComponentConfigurator componentConfigurator;

    /**
     * Builders for supported SBOM formats.
     */
    private final Set<BomBuilder> bomBuilders;

    /**
     * Used to retrieve instances of {@link EnforcerRule} by name.
     */
    private final PlexusContainer container;

    /**
     * Used to create a temporary local repository.
     */
    private final LocalRepositoryManagerFactory localRepositoryManagerFactory;

    @Inject
    public CheckMojo(
            MavenProject project,
            MavenSession session,
            MojoExecution mojoExecution,
            @Named("basic") ComponentConfigurator componentConfigurator,
            Set<BomBuilder> bomBuilders,
            PlexusContainer container,
            LocalRepositoryManagerFactory localRepositoryManagerFactory) {
        this.project = project;
        this.session = session;
        this.mojoExecution = mojoExecution;
        this.componentConfigurator = componentConfigurator;
        this.bomBuilders = bomBuilders;
        this.container = container;
        this.localRepositoryManagerFactory = localRepositoryManagerFactory;
    }

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        List<? extends EnforcerRule> rules = createEnforcerRules();

        for (Artifact artifact : project.getAttachedArtifacts()) {
            checkArtifact(artifact, rules);
        }
    }

    private void checkArtifact(Artifact bomArtifact, List<? extends EnforcerRule> rules)
            throws MojoExecutionException, MojoFailureException {
        org.eclipse.aether.artifact.Artifact mainBillOfMaterials = Artifacts.toArtifact(bomArtifact);
        for (BomBuilder bomBuilder : bomBuilders) {
            if (bomBuilder.isSupported(mainBillOfMaterials)) {
                try {
                    RepositorySystemSession effectiveRepoSession = usePrivateLocalRepo
                            ? new CustomLocalRepositorySystemSession(repoSession, createLocalRepositoryManager())
                            : repoSession;

                    // POM projects don't have a resolved artifact
                    org.eclipse.aether.artifact.Artifact artifact = Artifacts.toArtifact(project.getArtifact());
                    if ("pom".equals(project.getPackaging()) && artifact.getFile() == null) {
                        artifact = artifact.setFile(project.getFile());
                    }
                    BomBuilderRequest request = DefaultBomBuilderRequest.newBuilder()
                            .setArtifact(artifact)
                            .setMainBillOfMaterials(mainBillOfMaterials)
                            .get();

                    BillOfMaterials billOfMaterials = bomBuilder.build(effectiveRepoSession, request);
                    for (EnforcerRule rule : rules) {
                        rule.execute(billOfMaterials);
                    }
                } catch (BomBuildingException e) {
                    throw new MojoFailureException("Failed to parse BOM artifact " + mainBillOfMaterials, e);
                }
                break;
            }
        }
    }

    private LocalRepositoryManager createLocalRepositoryManager() throws MojoExecutionException {
        try {
            LocalRepository repository = new LocalRepository(privateLocalRepoPath.toFile());
            return localRepositoryManagerFactory.newInstance(repoSession, repository);
        } catch (NoLocalRepositoryManagerException e) {
            throw new MojoExecutionException(e);
        }
    }

    // package-private for testing
    List<? extends EnforcerRule> createEnforcerRules() throws MojoExecutionException {
        ExpressionEvaluator evaluator = new PluginParameterExpressionEvaluator(session, mojoExecution);

        List<EnforcerRule> enforcerRules = new ArrayList<>();
        ClassRealm realm =
                mojoExecution.getMojoDescriptor().getPluginDescriptor().getClassRealm();
        container.setLookupRealm(realm);
        for (PlexusConfiguration ruleConfig : rules.getChildren()) {
            try {
                EnforcerRule rule = container.lookup(EnforcerRule.class, ruleConfig.getName());
                componentConfigurator.configureComponent(rule, ruleConfig, evaluator, realm);
                enforcerRules.add(rule);
            } catch (ComponentLookupException e) {
                throw new MojoExecutionException(
                        "Failed to instantiate SBOM Enforcer rule `" + ruleConfig.getName() + "`", e);
            } catch (ComponentConfigurationException e) {
                throw new MojoExecutionException(
                        "Failed to configure SBOM Enforcer rule `" + ruleConfig.getName() + "`", e);
            }
        }
        return enforcerRules;
    }

    public void addRule(PlexusConfiguration rule) {
        rules.addChild(rule);
    }

    /**
     * Replaces the local repository manager to prevent the usage of artifacts installed locally.
     */
    private static class CustomLocalRepositorySystemSession extends AbstractForwardingRepositorySystemSession {

        private final RepositorySystemSession session;
        private final LocalRepositoryManager localRepositoryManager;

        CustomLocalRepositorySystemSession(RepositorySystemSession session, LocalRepositoryManager localRepositoryManager) {
            this.session = session;
            this.localRepositoryManager = localRepositoryManager;
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
        public LocalRepositoryManager getLocalRepositoryManager() {
            return localRepositoryManager;
        }
    }
}
