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

final String FAKE_SHA1 = 'b02c125db8b6d295adf72ae6e71af5d83bce2370'
final String REAL_SHA1 = 'fc5d727c85ef48d3326e009391851928c7113e0d'

File buildLog = new File(basedir, "build.log")
assert buildLog.exists()
List<String> errors = buildLog.readLines().findAll { it.startsWith("[ERROR]") }
assert errors.contains("[ERROR] * Invalid SHA1 checksum for file log4j-api-2.24.3.jar: expecting `$REAL_SHA1` but got `$FAKE_SHA1`".toString())