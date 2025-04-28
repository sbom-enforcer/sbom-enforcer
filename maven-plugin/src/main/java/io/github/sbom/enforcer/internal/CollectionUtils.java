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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Helper methods for nullable collections.
 */
public final class CollectionUtils {

    public static <K, V> Map<K, V> nullToEmpty(@Nullable Map<K, V> map) {
        return map != null ? map : Collections.emptyMap();
    }

    public static <E> List<E> nullToEmpty(@Nullable List<E> list) {
        return list != null ? list : Collections.emptyList();
    }

    private CollectionUtils() {}
}
