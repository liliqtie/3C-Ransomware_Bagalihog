import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

public class Decryption {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Kiss muna and i will send you the key :>>>");
        System.out.print("Key: ");
        String key = scanner.nextLine();

        // Initialize AES in GCM mode
        byte[] keyBytes = key.getBytes();
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        } catch (Exception e) {
            throw new RuntimeException("Error while setting up AES", e);
        }

        // Looping through target files
        try {
            Files.walk(Paths.get("./Document"))
                    .filter(Files::isRegularFile)
                    .forEach(path -> {
                        try {
                            // Skip if directory or not .enc file
                            if (path.toString().endsWith(".enc")) {
                                // Decrypt the file
                                System.out.println("Decrypting " + path + "...");

                                // Read file contents
                                byte[] encrypted = Files.readAllBytes(path);

                                // Decrypt bytes
                                byte[] decrypted = cipher.doFinal(encrypted);

                                // Write decrypted contents
                                Path decryptedFilePath = Paths.get(path.toString().replace(".enc", ""));
                                Files.write(decryptedFilePath, decrypted);

                                // Delete the encrypted file
                                Files.delete(path);
                            }
                        } catch (IOException | RuntimeException e) {
                            System.out.println("Error while processing file: " + path);
                            e.printStackTrace();
                        } catch (Exception e) {
                            System.out.println("Decryption failed for file: " + path);
                            e.printStackTrace();
                        }
                    });
        } catch (IOException e) {
            throw new RuntimeException("Error while walking through directory", e);
        }
    }
}
