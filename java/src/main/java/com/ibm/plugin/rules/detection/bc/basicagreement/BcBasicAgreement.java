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
package com.ibm.plugin.rules.detection.bc.basicagreement;

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBasicAgreement {

    private BcBasicAgreement() {
        // nothing
    }

    private static final List<String> basicAgreements =
            Arrays.asList(
                    "DHBasicAgreement",
                    "ECDHBasicAgreement",
                    "ECDHCBasicAgreement",
                    "ECDHCStagedAgreement",
                    "ECMQVBasicAgreement",
                    "MQVBasicAgreement",
                    "XDHBasicAgreement");

    private static @Nonnull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (String agreement : basicAgreements) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.agreement." + agreement)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(agreement))
                            .withoutParameters()
                            .buildForContext(new KeyContext(Map.of("kind", "DH")))
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcBasicAgreementInit.rules()));
        }

        return constructorsList;
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return simpleConstructors();
    }
}
