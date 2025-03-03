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

File buildLog = new File(basedir, "build.log")
assert buildLog.exists()
List<String> errors = buildLog.readLines().findAll { it.startsWith("[ERROR]") }
assert errors.contains('[ERROR] * Broken external reference (404): https://errorprone.info/error_prone_annotations')
assert errors.contains('[ERROR] * Broken external reference (404): https://github.com/google/error-prone/error_prone_annotations')