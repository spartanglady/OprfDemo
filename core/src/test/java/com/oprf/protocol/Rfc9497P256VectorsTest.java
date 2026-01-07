package com.oprf.protocol;

import com.oprf.CipherSuite;
import com.oprf.OprfMode;
import com.oprf.core.GroupElement;
import com.oprf.core.KeyPair;
import com.oprf.core.Proof;
import com.oprf.core.Scalar;
import com.oprf.util.ContextString;
import com.oprf.util.Serialization;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class Rfc9497P256VectorsTest {

    private static final byte[] SEED = hex(
            "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3" +
            "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
    private static final byte[] KEY_INFO = hex("74657374206b6579");
    private static final byte[] INFO = hex("7465737420696e666f");

    private static final byte[] BLIND = hex(
            "3338fa65ec36e0290022b48eb562889d" +
            "89dbfa691d1cde91517fa222ed7ad364");
    private static final byte[] BLIND_2 = hex(
            "f9db001266677f62c095021db018cd8c" +
            "bb55941d4073698ce45c405d1348b7b1");
    private static final byte[] PROOF_NONCE_BATCH = hex(
            "350e8040f828bf6ceca27405420cdf3d" +
            "63cb3aef005f40ba51943c8026877963");

    @Test
    void testDeriveKeyPairVectors() {
        KeyPair oprfKey = KeyPair.deriveKeyPair(OprfMode.BASE, SEED, KEY_INFO);
        assertArrayEquals(hex(
                "159749d750713afe245d2d39ccfaae83" +
                "81c53ce92d098a9375ee70739c7ac0bf"),
                oprfKey.exportPrivateKey());

        KeyPair voprfKey = KeyPair.deriveKeyPair(OprfMode.VERIFIABLE, SEED, KEY_INFO);
        assertArrayEquals(hex(
                "ca5d94c8807817669a51b196c34c1b7f" +
                "8442fde4334a7121ae4736364312fca6"),
                voprfKey.exportPrivateKey());
        assertArrayEquals(hex(
                "03e17e70604bcabe198882c0a1f27a92" +
                "441e774224ed9c702e51dd17038b102462"),
                voprfKey.exportPublicKey());

        KeyPair poprfKey = KeyPair.deriveKeyPair(OprfMode.PARTIAL, SEED, KEY_INFO);
        assertArrayEquals(hex(
                "6ad2173efa689ef2c27772566ad7ff6e" +
                "2d59b3b196f00219451fb2c89ee4dae2"),
                poprfKey.exportPrivateKey());
        assertArrayEquals(hex(
                "030d7ff077fddeec965db14b794f0cc1" +
                "ba9019b04a2f4fcc1fa525dedf72e2a3e3"),
                poprfKey.exportPublicKey());
    }

    @Test
    void testOprfVectors() {
        KeyPair keyPair = KeyPair.deriveKeyPair(OprfMode.BASE, SEED, KEY_INFO);
        assertOprfVector(
                keyPair,
                hex("00"),
                BLIND,
                hex("03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d"),
                hex("030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832"),
                hex("a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd")
        );
        assertOprfVector(
                keyPair,
                hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
                BLIND,
                hex("03cc1df781f1c2240a64d1c297b3f3d16262ef5d4cf102734882675c26231b0838"),
                hex("03a0395fe3828f2476ffcd1f4fe540e5a8489322d398be3c4e5a869db7fcb7c52c"),
                hex("c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce")
        );
    }

    @Test
    void testVoprfVectors() {
        KeyPair keyPair = KeyPair.deriveKeyPair(OprfMode.VERIFIABLE, SEED, KEY_INFO);
        assertVoprfVector(
                keyPair,
                hex("00"),
                BLIND,
                hex("02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da"),
                hex("0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2"),
                hex("e7c2b3c5c954c035949f1f74e6bce2ed539a3be267d1481e9ddb178533df4c2664f69d065c604a4fd953e100b856ad83804eb3845189babfa5a702090d6fc5fa"),
                BLIND_2,
                hex("0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1")
        );
        assertVoprfVector(
                keyPair,
                hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
                BLIND,
                hex("03cd0f033e791c4d79dfa9c6ed750f2ac009ec46cd4195ca6fd3800d1e9b887dbd"),
                hex("030d2985865c693bf7af47ba4d3a3813176576383d19aff003ef7b0784a0d83cf1"),
                hex("2787d729c57e3d9512d3aa9e8708ad226bc48e0f1750b0767aaff73482c44b8d2873d74ec88aebd3504961acea16790a05c542d9fbff4fe269a77510db00abab"),
                BLIND_2,
                hex("771e10dcd6bcd3664e23b8f2a710cfaaa8357747c4a8cbba03133967b5c24f18")
        );

        assertVoprfBatchVector(
                keyPair,
                List.of(
                        hex("00"),
                        hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
                ),
                List.of(
                        BLIND,
                        BLIND_2
                ),
                List.of(
                        hex("02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da"),
                        hex("03462e9ae64cae5b83ba98a6b360d942266389ac369b923eb3d557213b1922f8ab")
                ),
                List.of(
                        hex("0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2"),
                        hex("02bb24f4d838414aef052a8f044a6771230ca69c0a5677540fff738dd31bb69771")
                ),
                hex("bdcc351707d02a72ce49511c7db990566d29d6153ad6f8982fad2b435d6ce4d60da1e6b3fa740811bde34dd4fe0aa1b5fe6600d0440c9ddee95ea7fad7a60cf2"),
                PROOF_NONCE_BATCH,
                List.of(
                        hex("0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1"),
                        hex("771e10dcd6bcd3664e23b8f2a710cfaaa8357747c4a8cbba03133967b5c24f18")
                )
        );
    }

    @Test
    void testPoprfVectors() {
        KeyPair keyPair = KeyPair.deriveKeyPair(OprfMode.PARTIAL, SEED, KEY_INFO);
        assertPoprfVector(
                keyPair,
                hex("00"),
                INFO,
                BLIND,
                hex("031563e127099a8f61ed51eeede05d747a8da2be329b40ba1f0db0b2bd9dd4e2c0"),
                hex("02c5e5300c2d9e6ba7f3f4ad60500ad93a0157e6288eb04b67e125db024a2c74d2"),
                hex("f8a33690b87736c854eadfcaab58a59b8d9c03b569110b6f31f8bf7577f3fbb85a8a0c38468ccde1ba942be501654adb106167c8eb178703ccb42bccffb9231a"),
                BLIND_2,
                hex("193a92520bd8fd1f37accb918040a57108daa110dc4f659abe212636d245c592")
        );
        assertPoprfVector(
                keyPair,
                hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
                INFO,
                BLIND,
                hex("021a440ace8ca667f261c10ac7686adc66a12be31e3520fca317643a1eee9dcd4d"),
                hex("0208ca109cbae44f4774fc0bdd2783efdcb868cb4523d52196f700210e777c5de3"),
                hex("043a8fb7fc7fd31e35770cabda4753c5bf0ecc1e88c68d7d35a62bf2631e875af4613641be2d1875c31d1319d191c4bbc0d04875f4fd03c31d3d17dd8e069b69"),
                BLIND_2,
                hex("1e6d164cfd835d88a31401623549bf6b9b306628ef03a7962921d62bc5ffce8c")
        );

        assertPoprfBatchVector(
                keyPair,
                List.of(
                        hex("00"),
                        hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
                ),
                INFO,
                List.of(
                        BLIND,
                        BLIND_2
                ),
                List.of(
                        hex("031563e127099a8f61ed51eeede05d747a8da2be329b40ba1f0db0b2bd9dd4e2c0"),
                        hex("03ca4ff41c12fadd7a0bc92cf856732b21df652e01a3abdf0fa8847da053db213c")
                ),
                List.of(
                        hex("02c5e5300c2d9e6ba7f3f4ad60500ad93a0157e6288eb04b67e125db024a2c74d2"),
                        hex("02f0b6bcd467343a8d8555a99dc2eed0215c71898c5edb77a3d97ddd0dbad478e8")
                ),
                hex("8fbd85a32c13aba79db4b42e762c00687d6dbf9c8cb97b2a225645ccb00d9d7580b383c885cdfd07df448d55e06f50f6173405eee5506c0ed0851ff718d13e68"),
                PROOF_NONCE_BATCH,
                List.of(
                        hex("193a92520bd8fd1f37accb918040a57108daa110dc4f659abe212636d245c592"),
                        hex("1e6d164cfd835d88a31401623549bf6b9b306628ef03a7962921d62bc5ffce8c")
                )
        );
    }

    private static void assertOprfVector(KeyPair keyPair, byte[] input, byte[] blindBytes,
                                         byte[] expectedBlinded, byte[] expectedEvaluated,
                                         byte[] expectedOutput) {
        Scalar blind = Scalar.fromBytes(blindBytes);
        GroupElement inputElement = HashToCurve.hashToCurve(
                input, CipherSuite.getHashToCurveDST(OprfMode.BASE));
        GroupElement blindedElement = inputElement.multiply(blind);
        assertArrayEquals(expectedBlinded, blindedElement.toBytes());

        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.BASE, keyPair);
        GroupElement evaluatedElement = evaluator.evaluate(blindedElement).getEvaluatedElement();
        assertArrayEquals(expectedEvaluated, evaluatedElement.toBytes());

        GroupElement unblinded = evaluatedElement.multiply(blind.invert());
        byte[] output = finalizeOprf(input, unblinded.toBytes());
        assertArrayEquals(expectedOutput, output);
    }

    private static void assertVoprfVector(KeyPair keyPair, byte[] input, byte[] blindBytes,
                                          byte[] expectedBlinded, byte[] expectedEvaluated,
                                          byte[] expectedProof, byte[] proofNonce,
                                          byte[] expectedOutput) {
        Scalar blind = Scalar.fromBytes(blindBytes);
        GroupElement inputElement = HashToCurve.hashToCurve(
                input, CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE));
        GroupElement blindedElement = inputElement.multiply(blind);
        assertArrayEquals(expectedBlinded, blindedElement.toBytes());

        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.VERIFIABLE, keyPair);
        GroupElement evaluatedElement = evaluator.evaluate(blindedElement).getEvaluatedElement();
        assertArrayEquals(expectedEvaluated, evaluatedElement.toBytes());

        DleqProver prover = new DleqProver(OprfMode.VERIFIABLE);
        Proof proof = prover.generateBatchProofWithNonce(
                keyPair.getPrivateKey(),
                GroupElement.generator(),
                keyPair.getPublicKey(),
                List.of(blindedElement),
                List.of(evaluatedElement),
                Scalar.fromBytes(proofNonce)
        );
        assertArrayEquals(expectedProof, proof.toBytes());

        GroupElement unblinded = evaluatedElement.multiply(blind.invert());
        byte[] output = finalizeOprf(input, unblinded.toBytes());
        assertArrayEquals(expectedOutput, output);
    }

    private static void assertVoprfBatchVector(KeyPair keyPair,
                                               List<byte[]> inputs,
                                               List<byte[]> blinds,
                                               List<byte[]> expectedBlinded,
                                               List<byte[]> expectedEvaluated,
                                               byte[] expectedProof,
                                               byte[] proofNonce,
                                               List<byte[]> expectedOutputs) {
        List<GroupElement> blindedElements = new java.util.ArrayList<>(inputs.size());
        for (int i = 0; i < inputs.size(); i++) {
            Scalar blind = Scalar.fromBytes(blinds.get(i));
            GroupElement inputElement = HashToCurve.hashToCurve(
                    inputs.get(i), CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE));
            GroupElement blindedElement = inputElement.multiply(blind);
            assertArrayEquals(expectedBlinded.get(i), blindedElement.toBytes());
            blindedElements.add(blindedElement);
        }

        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.VERIFIABLE, keyPair);
        List<BlindEvaluate.EvaluationResult> results = evaluator.evaluateBatch(blindedElements);
        List<GroupElement> evaluatedElements = new java.util.ArrayList<>(results.size());
        for (int i = 0; i < results.size(); i++) {
            GroupElement evaluatedElement = results.get(i).getEvaluatedElement();
            assertArrayEquals(expectedEvaluated.get(i), evaluatedElement.toBytes());
            evaluatedElements.add(evaluatedElement);
        }

        DleqProver prover = new DleqProver(OprfMode.VERIFIABLE);
        Proof proof = prover.generateBatchProofWithNonce(
                keyPair.getPrivateKey(),
                GroupElement.generator(),
                keyPair.getPublicKey(),
                blindedElements,
                evaluatedElements,
                Scalar.fromBytes(proofNonce)
        );
        assertArrayEquals(expectedProof, proof.toBytes());

        for (int i = 0; i < inputs.size(); i++) {
            Scalar blind = Scalar.fromBytes(blinds.get(i));
            GroupElement unblinded = evaluatedElements.get(i).multiply(blind.invert());
            byte[] output = finalizeOprf(inputs.get(i), unblinded.toBytes());
            assertArrayEquals(expectedOutputs.get(i), output);
        }
    }

    private static void assertPoprfVector(KeyPair keyPair, byte[] input, byte[] info,
                                          byte[] blindBytes, byte[] expectedBlinded,
                                          byte[] expectedEvaluated, byte[] expectedProof,
                                          byte[] proofNonce, byte[] expectedOutput) {
        Scalar blind = Scalar.fromBytes(blindBytes);
        GroupElement inputElement = HashToCurve.hashToCurve(
                input, CipherSuite.getHashToCurveDST(OprfMode.PARTIAL));
        GroupElement blindedElement = inputElement.multiply(blind);
        assertArrayEquals(expectedBlinded, blindedElement.toBytes());

        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.PARTIAL, keyPair);
        GroupElement evaluatedElement = evaluator.evaluate(blindedElement, info).getEvaluatedElement();
        assertArrayEquals(expectedEvaluated, evaluatedElement.toBytes());

        Scalar m = hashInfoToScalar(info, OprfMode.PARTIAL);
        Scalar t = keyPair.getPrivateKey().add(m);
        GroupElement tweakedKey = keyPair.getPublicKey().add(GroupElement.generator().multiply(m));

        DleqProver prover = new DleqProver(OprfMode.PARTIAL);
        Proof proof = prover.generateBatchProofWithNonce(
                t,
                GroupElement.generator(),
                tweakedKey,
                List.of(evaluatedElement),
                List.of(blindedElement),
                Scalar.fromBytes(proofNonce)
        );
        assertArrayEquals(expectedProof, proof.toBytes());

        GroupElement unblinded = evaluatedElement.multiply(blind.invert());
        byte[] output = finalizePoprf(input, info, unblinded.toBytes());
        assertArrayEquals(expectedOutput, output);
    }

    private static void assertPoprfBatchVector(KeyPair keyPair,
                                               List<byte[]> inputs,
                                               byte[] info,
                                               List<byte[]> blinds,
                                               List<byte[]> expectedBlinded,
                                               List<byte[]> expectedEvaluated,
                                               byte[] expectedProof,
                                               byte[] proofNonce,
                                               List<byte[]> expectedOutputs) {
        List<GroupElement> blindedElements = new java.util.ArrayList<>(inputs.size());
        for (int i = 0; i < inputs.size(); i++) {
            Scalar blind = Scalar.fromBytes(blinds.get(i));
            GroupElement inputElement = HashToCurve.hashToCurve(
                    inputs.get(i), CipherSuite.getHashToCurveDST(OprfMode.PARTIAL));
            GroupElement blindedElement = inputElement.multiply(blind);
            assertArrayEquals(expectedBlinded.get(i), blindedElement.toBytes());
            blindedElements.add(blindedElement);
        }

        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.PARTIAL, keyPair);
        List<BlindEvaluate.EvaluationResult> results = evaluator.evaluateBatch(blindedElements, info);
        List<GroupElement> evaluatedElements = new java.util.ArrayList<>(results.size());
        for (int i = 0; i < results.size(); i++) {
            GroupElement evaluatedElement = results.get(i).getEvaluatedElement();
            assertArrayEquals(expectedEvaluated.get(i), evaluatedElement.toBytes());
            evaluatedElements.add(evaluatedElement);
        }

        Scalar m = hashInfoToScalar(info, OprfMode.PARTIAL);
        Scalar t = keyPair.getPrivateKey().add(m);
        GroupElement tweakedKey = keyPair.getPublicKey().add(GroupElement.generator().multiply(m));

        DleqProver prover = new DleqProver(OprfMode.PARTIAL);
        Proof proof = prover.generateBatchProofWithNonce(
                t,
                GroupElement.generator(),
                tweakedKey,
                evaluatedElements,
                blindedElements,
                Scalar.fromBytes(proofNonce)
        );
        assertArrayEquals(expectedProof, proof.toBytes());

        for (int i = 0; i < inputs.size(); i++) {
            Scalar blind = Scalar.fromBytes(blinds.get(i));
            GroupElement unblinded = evaluatedElements.get(i).multiply(blind.invert());
            byte[] output = finalizePoprf(inputs.get(i), info, unblinded.toBytes());
            assertArrayEquals(expectedOutputs.get(i), output);
        }
    }

    private static Scalar hashInfoToScalar(byte[] info, OprfMode mode) {
        byte[] framedInfo = ContextString.concat(
                ContextString.infoDst(mode),
                Serialization.i2osp2(info.length),
                info
        );
        return HashToCurve.hashToScalar(framedInfo, CipherSuite.getHashToScalarDST(mode));
    }

    private static byte[] finalizeOprf(byte[] input, byte[] unblindedElement) {
        byte[] hashInput = ContextString.concat(
                Serialization.i2osp2(input.length), input,
                Serialization.i2osp2(unblindedElement.length), unblindedElement,
                ContextString.finalizeDst(OprfMode.BASE)
        );
        return sha256(hashInput);
    }

    private static byte[] finalizePoprf(byte[] input, byte[] info, byte[] unblindedElement) {
        byte[] hashInput = ContextString.concat(
                Serialization.i2osp2(input.length), input,
                Serialization.i2osp2(info.length), info,
                Serialization.i2osp2(unblindedElement.length), unblindedElement,
                ContextString.finalizeDst(OprfMode.PARTIAL)
        );
        return sha256(hashInput);
    }

    private static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static byte[] hex(String value) {
        return hexToBytes(value);
    }

    private static byte[] hexToBytes(String hex) {
        String cleaned = hex.replaceAll("\\s+", "");
        int len = cleaned.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex length");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) Integer.parseInt(cleaned.substring(i, i + 2), 16);
        }
        return data;
    }
}
