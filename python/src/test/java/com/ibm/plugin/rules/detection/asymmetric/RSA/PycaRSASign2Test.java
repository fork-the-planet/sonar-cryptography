/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2024 IBM
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
package com.ibm.plugin.rules.detection.asymmetric.RSA;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class PycaRSASign2Test extends TestBase {

    @Test
    public void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/RSA/PycaRSASign2TestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PrivateKeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(KeySize.class);
        assertThat(value0.asString()).isEqualTo("2048");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1 =
                getStoreOfValueType(SignatureAction.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(SignatureAction.class);
        assertThat(value0_1.asString()).isEqualTo("SIGN");

        List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>> stores =
                getStoresOfValueType(ValueAction.class, store_1.getChildren());
        assertThat(stores).isNotNull();
        for (DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store : stores) {
            assertThat(store.getDetectionValues()).hasSize(1);
            assertThat(store.getDetectionValueContext())
                    .isInstanceOfAny(SignatureContext.class, DigestContext.class);
            IValue<Tree> v = store.getDetectionValues().get(0);
            assertThat(v).isInstanceOf(ValueAction.class);
            assertThat(v.asString())
                    .satisfiesAnyOf(
                            s -> assertThat(s).isEqualTo("PKCS1v15"),
                            s -> assertThat(s).isEqualTo("SHA3_384"));
        }

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // PrivateKey
        INode privateKeyNode = nodes.get(0);
        assertThat(privateKeyNode.getKind()).isEqualTo(PrivateKey.class);
        assertThat(privateKeyNode.getChildren()).hasSize(4);
        assertThat(privateKeyNode.asString()).isEqualTo("RSA");

        // KeyGeneration under PrivateKey
        INode keyGenerationNode = privateKeyNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.getChildren()).isEmpty();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // Sign under PrivateKey
        INode signNode = privateKeyNode.getChildren().get(Sign.class);
        assertThat(signNode).isNotNull();
        assertThat(signNode.getChildren()).isEmpty();
        assertThat(signNode.asString()).isEqualTo("SIGN");

        // KeyLength under PrivateKey
        INode keyLengthNode = privateKeyNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode).isNotNull();
        assertThat(keyLengthNode.getChildren()).isEmpty();
        assertThat(keyLengthNode.asString()).isEqualTo("2048");

        // Signature under PrivateKey
        INode signatureNode = privateKeyNode.getChildren().get(Signature.class);
        assertThat(signatureNode).isNotNull();
        assertThat(signatureNode.getChildren()).hasSize(2);
        assertThat(signatureNode.asString()).isEqualTo("RSA");

        // MessageDigest under Signature under PrivateKey
        INode messageDigestNode = signatureNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.getChildren()).hasSize(4);
        assertThat(messageDigestNode.asString()).isEqualTo("SHA3-384");

        // DigestSize under MessageDigest under Signature under PrivateKey
        INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
        assertThat(digestSizeNode).isNotNull();
        assertThat(digestSizeNode.getChildren()).isEmpty();
        assertThat(digestSizeNode.asString()).isEqualTo("384");

        // Oid under MessageDigest under Signature under PrivateKey
        INode oidNode = messageDigestNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.9");

        // BlockSize under MessageDigest under Signature under PrivateKey
        INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("832");

        // Digest under MessageDigest under Signature under PrivateKey
        INode digestNode = messageDigestNode.getChildren().get(Digest.class);
        assertThat(digestNode).isNotNull();
        assertThat(digestNode.getChildren()).isEmpty();
        assertThat(digestNode.asString()).isEqualTo("DIGEST");

        // Oid under Signature under PrivateKey
        INode oidNode1 = signatureNode.getChildren().get(Oid.class);
        assertThat(oidNode1).isNotNull();
        assertThat(oidNode1.getChildren()).isEmpty();
        assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.3.15");
    }
}