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
    private static RepositorySystemSession repoSession;

    @BeforeAll
    static void setup() throws Exception {
        container = MojoUtils.setupContainer();
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
        return new CheckMojo(null, session, mojoExecution, configurator, Set.of(), container, null);
    }

    private static PlexusConfiguration fromString(String configuration) {
        try {
            Xpp3Dom dom = Xpp3DomBuilder.build(new StringReader(configuration));
            return new XmlPlexusConfiguration(dom);
        } catch (XmlPullParserException | IOException e) {
            throw new AssertionError(e);
        }
    }

    private static PlexusConfiguration fromExample(Path path) {
        try {
            Path examples = Paths.get(System.getProperty("asciidoc.examples", "."));
            Path absolutePath = examples.resolve(path);
            assertThat(absolutePath).exists();
            try (Reader reader = Files.newBufferedReader(absolutePath, StandardCharsets.UTF_8)) {
                Xpp3Dom dom = Xpp3DomBuilder.build(reader);
                return new XmlPlexusConfiguration(dom.getChild("rules").getChild(0));
            }
        } catch (XmlPullParserException | IOException e) {
            throw new AssertionError(e);
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

    /**
     * Checks if the default values are as documented.
     */
    @Test
    void createEnforcerRules_validateReferences_defaultValuesFromDoc() throws Exception {
        CheckMojo mojo = createCheckMojo();
        mojo.addRule(fromExample(Paths.get("validateReferences.xml")));
        mojo.addRule(fromString("<validateReferences/>"));
        List<? extends EnforcerRule> rules = mojo.createEnforcerRules();
        assertThat(rules).hasSize(2).allMatch(rule -> rule instanceof ValidateReferencesRule);

        ValidateReferencesRule expectedRule = (ValidateReferencesRule) rules.get(0);
        ValidateReferencesRule actualRule = (ValidateReferencesRule) rules.get(1);
        assertThat(actualRule.isCheckDependencies())
                .as("checkDependencies")
                .isEqualTo(expectedRule.isCheckDependencies());
        assertThat(actualRule.isFailOnAuth()).as("failOnAuth").isEqualTo(expectedRule.isFailOnAuth());
        assertThat(actualRule.isFailOnRedirect()).as("failOnRedirect").isEqualTo(expectedRule.isFailOnRedirect());
        assertThat(actualRule.isFailOnDependencies())
                .as("failOnDependencies")
                .isEqualTo(expectedRule.isFailOnDependencies());
        assertThat(actualRule.getMaxFailuresPerHost())
                .as("maxFailuresPerHost")
                .isEqualTo(expectedRule.getMaxFailuresPerHost());
        assertThat(actualRule.getTimeoutMs()).as("timeoutMs").isEqualTo(expectedRule.getTimeoutMs());
        assertThat(actualRule.getIncludes()).as("includes").isEqualTo(expectedRule.getIncludes());
        assertThat(actualRule.getExcludes()).as("excludes").isEqualTo(expectedRule.getExcludes());
    }

    private static final PlexusConfiguration validateReferencesConfiguration = // language=xml
            fromString(
                    """
                    <validateReferences>
                      <checkDependencies>false</checkDependencies>
                      <failOnAuth>true</failOnAuth>
                      <failOnDependencies>true</failOnDependencies>
                      <failOnRedirect>true</failOnRedirect>
                      <maxFailuresPerHost>5</maxFailuresPerHost>
                      <timeoutMs>1000</timeoutMs>
                      <includes>
                        <include>foo</include>
                        <include>bar</include>
                      </includes>
                      <excludes>
                        <exclude>baz</exclude>
                      </excludes>
                    </validateReferences>""");

    @Test
    void createEnforcerRules_validateReferences() throws Exception {
        CheckMojo mojo = createCheckMojo();
        mojo.addRule(validateReferencesConfiguration);
        List<? extends EnforcerRule> rules = mojo.createEnforcerRules();
        assertThat(rules).hasSize(1);
        assertThat(rules.get(0)).isInstanceOf(ValidateReferencesRule.class);

        VerifyReferencesConfiguration expected = new VerifyReferencesConfiguration(
                false, true, true, true, 5, 1000, Set.of("foo", "bar"), Set.of("baz"));
        ValidateReferencesRule rule = (ValidateReferencesRule) rules.get(0);
        assertThat(rule.isCheckDependencies()).as("checkDependencies").isEqualTo(expected.checkDependencies());
        assertThat(rule.isFailOnAuth()).as("failOnAuth").isEqualTo(expected.failOnAuth());
        assertThat(rule.isFailOnRedirect()).as("failOnRedirect").isEqualTo(expected.failOnRedirect());
        assertThat(rule.isFailOnDependencies()).as("failOnDependencies").isEqualTo(expected.failOnDependencies());
        assertThat(rule.getMaxFailuresPerHost()).as("maxFailuresPerHost").isEqualTo(expected.maxFailuresPerHost());
        assertThat(rule.getTimeoutMs()).as("timeoutMs").isEqualTo(expected.timeoutMs());
        assertThat(rule.getIncludes()).as("includes").isEqualTo(expected.includes());
        assertThat(rule.getExcludes()).as("excludes").isEqualTo(expected.excludes());
    }

    record VerifyReferencesConfiguration(
            boolean checkDependencies,
            boolean failOnAuth,
            boolean failOnRedirect,
            boolean failOnDependencies,
            int maxFailuresPerHost,
            int timeoutMs,
            Set<String> includes,
            Set<String> excludes) {}

    static Stream<Arguments> createEnforcerRules_invalid() {
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
