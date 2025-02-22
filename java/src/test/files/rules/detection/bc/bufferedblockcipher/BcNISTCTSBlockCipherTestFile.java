import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.NISTCTSBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BcNISTCTSBlockCipherTestFile {

    public static void test1() {
        // Create a block cipher (AES in this case)
        BlockCipher cipher = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        // Initialize the cipher with the key
        byte[] keyData = "0123456789abcdef".getBytes(StandardCharsets.UTF_8); // 128-bit key
        KeyParameter key = new KeyParameter(keyData);

        // Set up the initialization vector (IV)
        byte[] ivData = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8); // 128-bit IV
        ParametersWithIV parametersWithIV = new ParametersWithIV(key, ivData);

        // Wrap the block cipher with NISTCTSBlockCipher
        NISTCTSBlockCipher ctsCipher =
                new NISTCTSBlockCipher(0, cipher); // Noncompliant {{(BlockCipher) AES-CTS}}

        // Initialize the NISTCTSBlockCipher with the parameters
        ctsCipher.init(true, parametersWithIV); // true for encryption, false for decryption
    }
}
