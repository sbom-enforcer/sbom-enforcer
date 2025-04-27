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
import io.github.sbom.enforcer.Component.ExternalReference;
import io.github.sbom.enforcer.EnforcerRule;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.inject.Named;
import org.apache.maven.plugin.MojoFailureException;
import org.codehaus.plexus.logging.Logger;
import org.jspecify.annotations.Nullable;

@Named("validateReferences")
public class ValidateReferencesRule implements EnforcerRule {

    private static final Set<Integer> RESPONSE_CODES_AUTH =
            Set.of(HttpURLConnection.HTTP_UNAUTHORIZED, HttpURLConnection.HTTP_FORBIDDEN);

    private static final Set<Integer> RESPONSE_CODES_REDIRECT =
            Set.of(HttpURLConnection.HTTP_MOVED_PERM, HttpURLConnection.HTTP_MOVED_TEMP);

    private static final int DEFAULT_MAX_FAILURES_PER_HOST = 3;

    private final Logger logger;
    private final HttpUrlChecker urlChecker;
    private final Map<String, Integer> failureCountByHost = new HashMap<>();
    private final Map<URI, Integer> responseCodeCache = new HashMap<>();

    /**
     * Fail on 401 or 403 response codes.
     */
    private boolean failOnAuth = false;

    /**
     * Fail on 301 or 302 response codes.
     */
    private boolean failOnRedirect = false;

    /**
     * Check references in dependencies
     */
    private boolean checkDependencies = true;

    /**
     * Consider broken links in dependencies as errors instead of warnings.
     */
    private boolean failOnDependencies = false;

    /**
     * Maximum IO errors per host
     */
    int maxFailuresPerHost = DEFAULT_MAX_FAILURES_PER_HOST;

    /**
     * List of external reference types to include in the check.
     */
    Set<String> includes = Set.of();

    /**
     * List of external reference types to exclude from the check.
     */
    Set<String> excludes = Set.of("distribution-intake");

    @Inject
    public ValidateReferencesRule(Logger logger) {
        this(logger, new JreHttpUrlChecker(logger));
    }

    ValidateReferencesRule(Logger logger, HttpUrlChecker urlChecker) {
        this.logger = logger;
        this.urlChecker = urlChecker;
    }

    @Override
    public void execute(BillOfMaterials bom) throws MojoFailureException {
        List<String> errors = new ArrayList<>(validateReferences(bom.getComponent()));
        List<String> dependencyErrors = new ArrayList<>();
        if (checkDependencies) {
            for (Component dependency : bom.getDependencies()) {
                dependencyErrors.addAll(validateReferences(dependency));
            }

            if (failOnDependencies) {
                errors.addAll(dependencyErrors);
            } else {
                dependencyErrors.stream().sorted().forEach(logger::warn);
            }
        }

        if (!errors.isEmpty()) {
            String message = errors.stream()
                    .sorted()
                    .collect(Collectors.joining(
                            "\n* ", "SBOM " + bom.getBillOfMaterials() + " contains invalid references:\n\n* ", ""));
            throw new MojoFailureException(message);
        }
    }

    private List<String> validateReferences(Component component) {
        return component.getExternalReferences().stream()
                .filter(this::shouldCheck)
                .<String>mapMulti((ref, consumer) -> {
                    String errorMessage = validateReference(ref.getLocation());
                    if (errorMessage != null) {
                        consumer.accept(errorMessage);
                    }
                })
                .toList();
    }

    private boolean shouldCheck(ExternalReference externalReference) {
        String referenceType = externalReference.getReferenceType();
        return (includes.isEmpty() || includes.contains(referenceType)) && !excludes.contains(referenceType);
    }

    @Nullable
    String validateReference(String location) {
        try {
            URI uri = new URI(location);
            String scheme = uri.getScheme();
            if ("http".equals(scheme) || "https".equals(scheme)) {
                URL url = uri.toURL();
                // 1. Skip if error limit exceeded
                Integer failureCount = failureCountByHost.get(url.getAuthority());
                if (failureCount != null && failureCount >= maxFailuresPerHost) {
                    logger.debug("Maximum IO errors reached for host: " + url.getAuthority());
                    return null;
                }
                // 2. Check the URL
                try {
                    Integer responseCode = responseCodeCache.get(uri);
                    if (responseCode == null) {
                        responseCode = urlChecker.getResponseCode(url);
                        responseCodeCache.put(uri, responseCode);
                    } else {
                        logger.debug("Using cached response for URL: " + url);
                    }
                    if (HttpURLConnection.HTTP_OK != responseCode
                            && (failOnAuth || !RESPONSE_CODES_AUTH.contains(responseCode))
                            && (failOnRedirect || !RESPONSE_CODES_REDIRECT.contains(responseCode))) {
                        return "Broken external reference (" + responseCode + "): " + location;
                    }
                } catch (IOException e) {
                    failureCountByHost.merge(url.getAuthority(), 1, Integer::sum);
                    return "Failed to connect to URL: " + location;
                }
            }
            return null;
        } catch (URISyntaxException | MalformedURLException e) {
            return "Reference location is not a valid URI: " + location;
        }
    }

    public boolean isCheckDependencies() {
        return checkDependencies;
    }

    public void setCheckDependencies(boolean checkDependencies) {
        this.checkDependencies = checkDependencies;
    }

    public boolean isFailOnAuth() {
        return failOnAuth;
    }

    public void setFailOnAuth(boolean failOnAuth) {
        this.failOnAuth = failOnAuth;
    }

    public boolean isFailOnRedirect() {
        return failOnRedirect;
    }

    public void setFailOnRedirect(boolean failOnRedirect) {
        this.failOnRedirect = failOnRedirect;
    }

    public boolean isFailOnDependencies() {
        return failOnDependencies;
    }

    public void setFailOnDependencies(boolean failOnDependencies) {
        this.failOnDependencies = failOnDependencies;
    }

    public int getMaxFailuresPerHost() {
        return maxFailuresPerHost;
    }

    public void setMaxFailuresPerHost(int maxFailuresPerHost) {
        this.maxFailuresPerHost = maxFailuresPerHost;
    }

    public int getTimeoutMs() {
        return urlChecker.getTimeoutMs();
    }
    /**
     * Timeout in milliseconds for HTTP/HTTPS requests
     */
    public void setTimeoutMs(int timeoutMs) {
        urlChecker.setTimeoutMs(timeoutMs);
    }

    public Set<String> getIncludes() {
        return Collections.unmodifiableSet(includes);
    }

    public void setIncludes(Set<String> includes) {
        this.includes = includes;
    }

    public Set<String> getExcludes() {
        return Collections.unmodifiableSet(excludes);
    }

    public void setExcludes(Set<String> excludes) {
        this.excludes = excludes;
    }

    interface HttpUrlChecker {

        /**
         * Checks the given URL and returns the response code.
         *
         * @param url A URL
         * @return An HTTP Response code
         * @throws IOException if a connection error occurs.
         */
        int getResponseCode(URL url) throws IOException;

        int getTimeoutMs();

        void setTimeoutMs(int timeoutMs);
    }

    static class JreHttpUrlChecker implements HttpUrlChecker {

        /**
         * HTTP connection and read timeout in milliseconds.
         */
        private int timeoutMs = 5000;

        private final Logger logger;

        JreHttpUrlChecker(Logger logger) {
            this.logger = logger;
        }

        @Override
        public int getTimeoutMs() {
            return timeoutMs;
        }

        @Override
        public void setTimeoutMs(int timeoutMs) {
            this.timeoutMs = timeoutMs;
        }

        @Override
        public int getResponseCode(URL url) throws IOException {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            try {
                connection.setRequestMethod("HEAD");
                connection.setInstanceFollowRedirects(false);
                connection.setDoInput(true);
                connection.setDoOutput(false);
                connection.setUseCaches(false);
                connection.setConnectTimeout(timeoutMs);
                connection.setReadTimeout(timeoutMs);
                logger.debug("Checking URL: " + url);
                connection.connect();
                return connection.getResponseCode();
            } finally {
                connection.disconnect();
            }
        }
    }
}
