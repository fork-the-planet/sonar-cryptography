/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.detection.jca.keyfactory;

import static com.ibm.plugin.rules.detection.TypeShortcuts.KEY_SPEC_TYPE;

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.jca.keyspec.JcaKeySpec;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaKeyFactoryGenerate {

    private static final IDetectionRule<Tree> GENERATE_PRIVATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.KeyFactory")
                    .forMethods("generatePrivate")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withMethodParameter(KEY_SPEC_TYPE)
                    .addDependingDetectionRules(JcaKeySpec.rules())
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATE_PUBLIC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.KeyFactory")
                    .forMethods("generatePublic")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withMethodParameter(KEY_SPEC_TYPE)
                    .addDependingDetectionRules(JcaKeySpec.rules())
                    .buildForContext(new PublicKeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private JcaKeyFactoryGenerate() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(GENERATE_PRIVATE, GENERATE_PUBLIC);
    }
}
