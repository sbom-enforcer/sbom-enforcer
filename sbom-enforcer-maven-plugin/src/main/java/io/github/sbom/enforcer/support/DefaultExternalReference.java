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
package io.github.sbom.enforcer.support;

import io.github.sbom.enforcer.Component.ExternalReference;
import java.util.Comparator;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * An {@link ExternalReference} implementation with a deterministic sorting order.
 */
public final class DefaultExternalReference implements ExternalReference, Comparable<DefaultExternalReference> {

    private final String referenceType;
    private final String location;
    private final @Nullable String contentType;

    public static ExternalReference of(String referenceType, String location) {
        return new DefaultExternalReference(
                Objects.requireNonNull(referenceType), Objects.requireNonNull(location), null);
    }

    private DefaultExternalReference(String referenceType, String location, @Nullable String contentType) {
        this.referenceType = referenceType;
        this.location = location;
        this.contentType = contentType;
    }

    @Override
    public String getReferenceType() {
        return referenceType;
    }

    @Override
    public String getLocation() {
        return location;
    }

    @Override
    public @Nullable String getContentType() {
        return contentType;
    }

    @Override
    public int compareTo(DefaultExternalReference other) {
        return compare(this, other);
    }

    static int compare(ExternalReference left, ExternalReference right) {
        int result = left.getReferenceType().compareTo(right.getReferenceType());
        if (result == 0) {
            result = left.getLocation().compareTo(right.getLocation());
        }
        if (result == 0) {
            result = Comparator.nullsFirst(String::compareTo).compare(left.getContentType(), right.getContentType());
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ExternalReference)) return false;
        ExternalReference that = (ExternalReference) o;
        return getReferenceType().equals(that.getReferenceType())
                && getLocation().equals(that.getLocation())
                && Objects.equals(getContentType(), that.getContentType());
    }

    @Override
    public int hashCode() {
        return Objects.hash(referenceType, location, contentType);
    }
}
