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

import java.nio.file.Path;
import org.codehaus.plexus.ContainerConfiguration;
import org.codehaus.plexus.DefaultContainerConfiguration;
import org.codehaus.plexus.DefaultPlexusContainer;
import org.codehaus.plexus.PlexusConstants;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.PlexusContainerException;
import org.codehaus.plexus.classworlds.ClassWorld;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositoryException;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.LocalRepositoryManager;
import org.eclipse.aether.spi.localrepo.LocalRepositoryManagerFactory;

public final class MojoUtils {

    private static ContainerConfiguration setupContainerConfiguration() {
        ClassWorld classWorld =
                new ClassWorld("plexus.core", Thread.currentThread().getContextClassLoader());
        return new DefaultContainerConfiguration()
                .setClassWorld(classWorld)
                .setClassPathScanning(PlexusConstants.SCANNING_INDEX)
                .setAutoWiring(true)
                .setName("maven");
    }

    public static PlexusContainer setupContainer() throws PlexusContainerException {
        return new DefaultPlexusContainer(setupContainerConfiguration());
    }

    public static RepositorySystemSession createRepositorySystemSession(
            PlexusContainer container, Path localRepositoryPath) throws ComponentLookupException, RepositoryException {
        LocalRepositoryManagerFactory factory = container.lookup(LocalRepositoryManagerFactory.class, "simple");
        DefaultRepositorySystemSession repoSession = new DefaultRepositorySystemSession();
        LocalRepositoryManager manager =
                factory.newInstance(repoSession, new LocalRepository(localRepositoryPath.toFile()));
        repoSession.setLocalRepositoryManager(manager);
        return repoSession;
    }

    private MojoUtils() {}
}
