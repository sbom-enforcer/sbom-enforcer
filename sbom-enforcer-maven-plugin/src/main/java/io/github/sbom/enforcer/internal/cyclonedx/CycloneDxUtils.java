/*
 * Copyright © 2025 Christian Grobmeier, Piotr P. Karwasz
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
import io.github.sbom.enforcer.BomBuildingException;
import java.io.File;
import java.util.HashMap;
import java.util.Map;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.Parser;
import org.cyclonedx.parsers.XmlParser;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.ArtifactProperties;
import org.eclipse.aether.artifact.DefaultArtifact;

public final class CycloneDxUtils {

    // Package URL qualifiers
    private static final String CLASSIFIER = "classifier";
    private static final String REPOSITORY_URL = "repository_url";

    static final String CYCLONE_DX_CLASSIFIER = "cyclonedx";
    private static final String XML = "xml";
    private static final String JSON = "json";

    public static Bom parseArtifact(Artifact artifact) throws BomBuildingException {
        File file = artifact.getFile();
        try {
            Parser parser = XML.equals(getCycloneDxFormat(artifact)) ? new XmlParser() : new JsonParser();
            return parser.parse(file);
        } catch (IllegalArgumentException | ParseException e) {
            throw new BomBuildingException("Failed to parse BOM file: " + file, e);
        }
    }

    public static Artifact toArtifact(Component component) throws BomBuildingException {
        PackageURL packageURL = toPackageURL(component);
        Map<String, String> qualifiers = packageURL.getQualifiers();
        String type = qualifiers.getOrDefault(ArtifactProperties.TYPE, "jar");
        String classifier = qualifiers.get(CLASSIFIER);
        String repositoryUrl = qualifiers.get(REPOSITORY_URL);
        // Set up properties of Aether artifact
        Map<String, String> properties = new HashMap<>();
        properties.put(ArtifactProperties.TYPE, type);
        if (repositoryUrl != null) {
            properties.put(io.github.sbom.enforcer.Component.Properties.REPOSITORY_URL, repositoryUrl);
        }
        return new DefaultArtifact(
                        packageURL.getNamespace(), packageURL.getName(), classifier, type, packageURL.getVersion())
                .setProperties(properties);
    }

    private static PackageURL toPackageURL(Component component) throws BomBuildingException {
        String purl = component.getPurl();
        if (purl == null) {
            throw new BomBuildingException("Missing pURL for dependency: " + component);
        }
        try {
            return new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            throw new BomBuildingException("Invalid pURL for dependency: " + component, e);
        }
    }

    private static String getCycloneDxFormat(Artifact artifact) {
        if (CYCLONE_DX_CLASSIFIER.equals(artifact.getClassifier())) {
            return switch (artifact.getExtension()) {
                case XML -> XML;
                case JSON -> JSON;
                default -> throw new IllegalArgumentException(
                        "Unsupported CycloneDX artifact type: " + artifact.getExtension() + ".");
            };
        }
        throw new IllegalArgumentException("Artifact " + artifact + " is not a CycloneDX document.");
    }

    private CycloneDxUtils() {}
}
