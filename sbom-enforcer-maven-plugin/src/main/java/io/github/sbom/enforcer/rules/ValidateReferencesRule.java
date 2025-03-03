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

import io.github.sbom.enforcer.BillOfMaterials;
import io.github.sbom.enforcer.Component;
import io.github.sbom.enforcer.EnforcerRule;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.inject.Named;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Parameter;
import org.codehaus.plexus.logging.Logger;
import org.jspecify.annotations.Nullable;

@Named("validateReferences")
public class ValidateReferencesRule implements EnforcerRule {

    private static final Set<Integer> RESPONSE_CODES_AUTH =
            Set.of(HttpURLConnection.HTTP_UNAUTHORIZED, HttpURLConnection.HTTP_FORBIDDEN);

    private static final Set<Integer> RESPONSE_CODES_REDIRECT =
            Set.of(HttpURLConnection.HTTP_MOVED_PERM, HttpURLConnection.HTTP_MOVED_TEMP);

    private final Logger logger;

    @Parameter(defaultValue = "false")
    private boolean failOnAuth;

    @Parameter(defaultValue = "false")
    private boolean failOnRedirect;

    @Parameter(defaultValue = "false")
    private boolean failOnDependencyReferences;

    @Inject
    public ValidateReferencesRule(Logger logger) {
        this.logger = logger;
    }

    @Override
    public void execute(BillOfMaterials bom) throws MojoFailureException {
        List<String> errors = new ArrayList<>(validateReferences(bom.getComponent()));
        List<String> dependencyErrors = new ArrayList<>();
        for (Component dependency : bom.getDependencies()) {
            dependencyErrors.addAll(validateReferences(dependency));
        }

        if (failOnDependencyReferences) {
            errors.addAll(dependencyErrors);
        } else {
            dependencyErrors.stream().sorted().forEach(logger::warn);
        }

        if (!errors.isEmpty()) {
            String message = errors.stream()
                    .sorted()
                    .collect(Collectors.joining(
                            "\n* ", "SBOM " + bom.getBillOfMaterials() + " contains invalid references:\n\n* ", ""));
            throw new MojoFailureException(message);
        }
    }

    List<String> validateReferences(Component component) {
        return component.getExternalReferences().stream()
                .<String>mapMulti((ref, consumer) -> {
                    String errorMessage = validateReference(ref.getLocation());
                    if (errorMessage != null) {
                        consumer.accept(errorMessage);
                    }
                })
                .toList();
    }

    @Nullable
    String validateReference(String location) {
        try {
            URI uri = new URI(location);
            String scheme = uri.getScheme();
            if ("http".equals(scheme) || "https".equals(scheme)) {
                int responseCode = checkHttpUrl(uri.toURL());
                if (HttpURLConnection.HTTP_OK != responseCode
                        && (failOnAuth || !RESPONSE_CODES_AUTH.contains(responseCode))
                        && (failOnRedirect || !RESPONSE_CODES_REDIRECT.contains(responseCode))) {
                    return "Broken external reference (" + responseCode + "): " + location;
                }
            }
        } catch (URISyntaxException | MalformedURLException e) {
            return "Reference location is not an URI: " + location;
        } catch (IOException e) {
            return "Failed to connect to URL: " + location;
        }
        return null;
    }

    static int checkHttpUrl(URL url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        try {
            connection.setRequestMethod("HEAD");
            connection.setInstanceFollowRedirects(false);
            connection.setDoInput(true);
            connection.setDoOutput(false);
            connection.setUseCaches(false);
            connection.connect();
            return connection.getResponseCode();
        } finally {
            connection.disconnect();
        }
    }
}
