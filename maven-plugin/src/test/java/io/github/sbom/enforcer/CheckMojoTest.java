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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.sbom.enforcer.internal.MojoUtils;
import io.github.sbom.enforcer.rules.ChecksumRule;
import io.github.sbom.enforcer.rules.ValidateReferencesRule;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenExecutionResult;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.descriptor.MojoDescriptor;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.assertj.core.api.Assertions;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.component.configurator.ComponentConfigurator;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.codehaus.plexus.configuration.PlexusConfiguration;
import org.codehaus.plexus.configuration.xml.XmlPlexusConfiguration;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.codehaus.plexus.util.xml.Xpp3DomBuilder;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CheckMojoTest {

    @TempDir
    private static Path localRepositoryPath;

    private static PlexusContainer container;
    private static RepositorySystem repoSystem;
    private static RepositorySystemSession repoSession;

    @BeforeAll
    static void setup() throws Exception {
        container = MojoUtils.setupContainer();
        repoSystem = container.lookup(RepositorySystem.class);
        repoSession = MojoUtils.createRepositorySystemSession(container, localRepositoryPath);
    }

    private static MojoDescriptor createMojoDescriptor() {
        PluginDescriptor pluginDescriptor = new PluginDescriptor();
        pluginDescriptor.setClassRealm(container.getContainerRealm());
        MojoDescriptor mojoDescriptor = new MojoDescriptor();
        mojoDescriptor.setPluginDescriptor(pluginDescriptor);
        return mojoDescriptor;
    }

    private static MavenExecutionRequest createMavenExecutionRequest() {
        MavenExecutionRequest request = mock(MavenExecutionRequest.class);
        Properties emptyProps = new Properties();
        when(request.getSystemProperties()).thenReturn(emptyProps);
        when(request.getUserProperties()).thenReturn(emptyProps);
        return request;
    }

    @SuppressWarnings("deprecation")
    private static MavenSession createMavenSession(MavenExecutionRequest request, MavenExecutionResult result) {
        return new MavenSession(container, repoSession, request, result);
    }

    private static CheckMojo createCheckMojo() throws ComponentLookupException {
        ComponentConfigurator configurator = container.lookup(ComponentConfigurator.class, "basic");
        MavenExecutionRequest request = createMavenExecutionRequest();
        MavenExecutionResult result = mock(MavenExecutionResult.class);
        MavenSession session = createMavenSession(request, result);
        MojoExecution mojoExecution = new MojoExecution(createMojoDescriptor());
        return new CheckMojo(null, session, mojoExecution, configurator, Set.of(), container);
    }

    private static PlexusConfiguration fromString(String configuration) throws IOException, XmlPullParserException {
        Xpp3Dom dom = Xpp3DomBuilder.build(new StringReader(configuration));
        return new XmlPlexusConfiguration(dom);
    }

    private static PlexusConfiguration fromExample(Path path) throws IOException, XmlPullParserException {
        Path examples = Paths.get(System.getProperty("asciidoc.examples", "."));
        Path absolutePath = examples.resolve(path);
        assertThat(absolutePath).exists();
        try (Reader reader = Files.newBufferedReader(absolutePath, StandardCharsets.UTF_8)) {
            Xpp3Dom dom = Xpp3DomBuilder.build(reader);
            return new XmlPlexusConfiguration(dom.getChild("rules").getChild(0));
        }
    }

    @Test
    void createEnforcerRules_checksum() throws Exception {
        CheckMojo mojo = createCheckMojo();
        mojo.addRule(fromString("<checksum/>"));
        List<? extends EnforcerRule> rules = mojo.createEnforcerRules();
        assertThat(rules).hasSize(1);
        assertThat(rules.get(0)).isInstanceOf(ChecksumRule.class);
    }

    static Stream<Arguments> createEnforcerRules_validateReferences() throws IOException, XmlPullParserException {
        return Stream.of(
                Arguments.of(
                        fromString("<validateReferences/>"),
                        new VerifyReferencesConfiguration(false, false, false, 3, 5000)),
                Arguments.of(
                        fromExample(Paths.get("validateReferences.xml")),
                        new VerifyReferencesConfiguration(true, true, true, 5, 1000)));
    }

    @ParameterizedTest
    @MethodSource
    void createEnforcerRules_validateReferences(PlexusConfiguration xmlRule, VerifyReferencesConfiguration expected)
            throws Exception {
        CheckMojo mojo = createCheckMojo();
        mojo.addRule(xmlRule);
        List<? extends EnforcerRule> rules = mojo.createEnforcerRules();
        assertThat(rules).hasSize(1);
        assertThat(rules.get(0)).isInstanceOf(ValidateReferencesRule.class);

        ValidateReferencesRule rule = (ValidateReferencesRule) rules.get(0);
        assertThat(rule.isFailOnAuth()).as("failOnAuth").isEqualTo(expected.failOnAuth());
        assertThat(rule.isFailOnRedirect()).as("failOnRedirect").isEqualTo(expected.failOnRedirect());
        assertThat(rule.isFailOnDependencyReferences())
                .as("failOnDependencyReferences")
                .isEqualTo(expected.failOnDependencyReferences());
        assertThat(rule.getMaxFailuresPerHost()).as("maxFailuresPerHost").isEqualTo(expected.maxFailuresPerHost());
        assertThat(rule.getTimeoutMs()).as("timeoutMs").isEqualTo(expected.timeoutMs());
    }

    record VerifyReferencesConfiguration(
            boolean failOnAuth,
            boolean failOnRedirect,
            boolean failOnDependencyReferences,
            int maxFailuresPerHost,
            int timeoutMs) {}

    static Stream<Arguments> createEnforcerRules_invalid() throws IOException, XmlPullParserException {
        return Stream.of(
                Arguments.of(fromString("<invalidRule/>"), "Failed to instantiate"),
                Arguments.of(
                        fromString(
                                """
                        <checksum>
                          <invalidProperty>42</invalidProperty>
                        </checksum>"""),
                        "Failed to configure"));
    }

    @ParameterizedTest
    @MethodSource
    void createEnforcerRules_invalid(PlexusConfiguration xmlRule, String errorMessage) throws Exception {
        CheckMojo mojo = createCheckMojo();
        mojo.addRule(xmlRule);
        Assertions.assertThatThrownBy(mojo::createEnforcerRules)
                .isInstanceOf(MojoExecutionException.class)
                .hasMessageContaining(errorMessage);
    }
}
