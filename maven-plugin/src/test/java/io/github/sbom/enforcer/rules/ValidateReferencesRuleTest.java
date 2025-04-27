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
package io.github.sbom.enforcer.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.Component;
import io.github.sbom.enforcer.rules.ValidateReferencesRule.HttpUrlChecker;
import io.github.sbom.enforcer.rules.ValidateReferencesRule.JreHttpUrlChecker;
import io.github.sbom.enforcer.support.DefaultBillOfMaterials;
import io.github.sbom.enforcer.support.DefaultComponent;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.channels.ServerSocketChannel;
import java.util.Map;
import java.util.stream.Stream;
import org.apache.maven.plugin.MojoFailureException;
import org.codehaus.plexus.logging.Logger;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class ValidateReferencesRuleTest {

    private static final URL URL_200;
    private static final URL URL_301;
    private static final URL URL_302;
    private static final URL URL_401;
    private static final URL URL_403;
    private static final URL URL_EXCEPTION;

    private static final String SSH_URL = "ssh://git@example/repo.git";
    private static final String INVALID_URL = "invalid url";

    static {
        try {
            URL_200 = new URL("https://example/200");
            URL_301 = new URL("http://example/301");
            URL_302 = new URL("https://example/302");
            URL_401 = new URL("https://example/401");
            URL_403 = new URL("https://example/403");
            URL_EXCEPTION = new URL("https://example/exception");
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    static Stream<Arguments> urlChecker_works() {
        return Stream.of(
                Arguments.of("https://logging.apache.org/log4j/2.x/index.html", HttpURLConnection.HTTP_OK),
                Arguments.of("https://logging.apache.org/log4j/2.x", HttpURLConnection.HTTP_MOVED_PERM),
                Arguments.of("https://logging.apache.org/not-found", HttpURLConnection.HTTP_NOT_FOUND));
    }

    @ParameterizedTest
    @MethodSource
    void urlChecker_works(String link, int expectedCode) throws IOException {
        URL url = new URL(link);
        JreHttpUrlChecker urlChecker = new JreHttpUrlChecker(mock(Logger.class));
        assertThat(urlChecker.getResponseCode(url)).isEqualTo(expectedCode);
    }

    @Test
    @Timeout(2)
    void urlChecker_whenNoAnswer_timeoutOccurs() throws IOException {
        try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            serverSocketChannel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            InetSocketAddress localAddress = (InetSocketAddress) serverSocketChannel.getLocalAddress();
            URL url = new URL("https://" + localAddress.getHostName() + ":" + localAddress.getPort());
            JreHttpUrlChecker urlChecker = new JreHttpUrlChecker(mock(Logger.class));
            urlChecker.setTimeoutMs(500);
            assertThatThrownBy(() -> urlChecker.getResponseCode(url)).isInstanceOf(SocketTimeoutException.class);
        }
    }

    private static HttpUrlChecker createMockHttpUrlChecker() throws IOException {
        HttpUrlChecker urlChecker = mock(HttpUrlChecker.class);
        when(urlChecker.getResponseCode(URL_200)).thenReturn(200);
        when(urlChecker.getResponseCode(URL_301)).thenReturn(301);
        when(urlChecker.getResponseCode(URL_302)).thenReturn(302);
        when(urlChecker.getResponseCode(URL_401)).thenReturn(401);
        when(urlChecker.getResponseCode(URL_403)).thenReturn(403);
        when(urlChecker.getResponseCode(URL_EXCEPTION)).thenThrow(new IOException("Test exception"));
        return urlChecker;
    }

    static Stream<Arguments> validateReference_successfulConnection() {
        return Stream.of(
                Arguments.of(false, false, URL_200.toExternalForm(), false),
                Arguments.of(false, false, URL_301.toExternalForm(), false),
                Arguments.of(false, false, URL_302.toExternalForm(), false),
                Arguments.of(false, false, URL_401.toExternalForm(), false),
                Arguments.of(true, false, URL_301.toExternalForm(), true),
                Arguments.of(true, false, URL_302.toExternalForm(), true),
                Arguments.of(true, false, URL_401.toExternalForm(), false),
                Arguments.of(false, true, URL_301.toExternalForm(), false),
                Arguments.of(false, true, URL_302.toExternalForm(), false),
                Arguments.of(false, true, URL_401.toExternalForm(), true),
                Arguments.of(false, false, SSH_URL, false));
    }

    @ParameterizedTest
    @MethodSource
    void validateReference_successfulConnection(
            boolean failOnRedirect, boolean failOnAuth, String location, boolean failure) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        rule.setFailOnRedirect(failOnRedirect);
        rule.setFailOnAuth(failOnAuth);

        String message = rule.validateReference(location);
        if (failure) {
            assertThat(message).as("error message").isNotNull().contains("Broken external reference");
        } else {
            assertThat(message).as("error message").isNull();
        }
    }

    static Stream<Arguments> validateReference_failedConnection() {
        return Stream.of(
                Arguments.of(URL_EXCEPTION.toExternalForm(), "Failed to connect"),
                Arguments.of(INVALID_URL, "not a valid URI"));
    }

    @ParameterizedTest
    @MethodSource
    void validateReference_failedConnection(String location, String errorMessage) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);

        assertThat(rule.validateReference(location))
                .as("error message")
                .isNotNull()
                .contains(errorMessage);
    }

    @ParameterizedTest
    @ValueSource(ints = 10)
    @NullSource
    void validateReference_failureCount(@Nullable Integer maxFailuresPerHost) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        if (maxFailuresPerHost != null) {
            rule.setMaxFailuresPerHost(maxFailuresPerHost);
        }

        int i;
        for (i = 0; i < rule.maxFailuresPerHost; i++) {
            assertThat(rule.validateReference(URL_EXCEPTION.toExternalForm()))
                    .as("error message on attempt %d", i + 1)
                    .contains("Failed to connect");
        }
        assertThat(rule.validateReference(URL_EXCEPTION.toExternalForm()))
                .as("error message on attempt %d", i + 1)
                .isNull();
    }

    @Test
    void validateReference_caching() throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);

        rule.validateReference(URL_301.toExternalForm());
        verify(urlChecker, times(1)).getResponseCode(URL_301);
        rule.validateReference(URL_301.toExternalForm());
        verify(urlChecker, times(1)).getResponseCode(URL_301);
    }

    static Stream<Arguments> failOnDependencies() {
        return Stream.of(
                // Dependencies disabled
                Arguments.of(false, false),
                // Check, but don't fail
                Arguments.of(true, false),
                // Check and fail
                Arguments.of(true, true));
    }

    @ParameterizedTest
    @MethodSource
    void failOnDependencies(boolean checkDependencies, boolean failOnDependencies) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        rule.setCheckDependencies(checkDependencies);
        rule.setFailOnDependencies(failOnDependencies);
        // Create BOM
        BillOfMaterials bom = createMockBillOfMaterials(Map.of(), Map.of("website", URL_EXCEPTION.toExternalForm()));

        if (checkDependencies && failOnDependencies) {
            assertThatThrownBy(() -> rule.execute(bom)).isInstanceOf(MojoFailureException.class);
        } else {
            assertDoesNotThrow(() -> rule.execute(bom));
        }
        if (checkDependencies) {
            verify(urlChecker, times(1)).getResponseCode(URL_EXCEPTION);
        } else {
            verify(urlChecker, never()).getResponseCode(any());
        }
    }

    static Stream<Arguments> failsOnMainComponent() {
        return Stream.of(Arguments.of(URL_EXCEPTION, true), Arguments.of(URL_200, false));
    }

    @ParameterizedTest
    @MethodSource
    void failsOnMainComponent(URL url, boolean failure) throws IOException {
        HttpUrlChecker urlChecker = createMockHttpUrlChecker();
        Logger logger = mock(Logger.class);
        ValidateReferencesRule rule = new ValidateReferencesRule(logger, urlChecker);
        // Create BOM
        BillOfMaterials bom = createMockBillOfMaterials(Map.of("website", url.toExternalForm()), Map.of());

        if (failure) {
            assertThatThrownBy(() -> rule.execute(bom))
                    .isInstanceOf(MojoFailureException.class)
                    .hasMessageContaining(url.toExternalForm());
        } else {
            assertDoesNotThrow(() -> rule.execute(bom));
        }
    }

    private static BillOfMaterials createMockBillOfMaterials(
            Map<String, String> componentReferences, Map<String, String> dependencyReferences) {
        DefaultBillOfMaterials.Builder builder = DefaultBillOfMaterials.newBuilder()
                .setBillOfMaterials(new DefaultArtifact("groupId:artifactId:xml:cyclonedx:1.0.0"));
        return builder.setComponent(createComponent(componentReferences))
                .addDependency(createComponent(dependencyReferences))
                .get();
    }

    private static Component createComponent(Map<String, String> externalReferences) {
        DefaultComponent.Builder builder =
                DefaultComponent.newBuilder().setArtifact(new DefaultArtifact("groupId:artifactId:1.0.0"));
        externalReferences.forEach(builder::addExternalReference);
        return builder.get();
    }
}
