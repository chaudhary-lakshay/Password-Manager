package PasswordManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import java.util.Arrays;
import java.util.Set;

public class PasswordManager {

    private record LoadedVault(byte[] salt, String verifier, Map<String, String> passwordStore) {}

    private CryptoUtil cryptoUtil;
    private Map<String, String> passwordStore = new HashMap<>();
    protected String vaultFile = null;
    protected byte[] salt = null;
    protected String verifier = null;

    public PasswordManager(CryptoUtil cryptoUtil, byte[] salt) {
        this.cryptoUtil = cryptoUtil;
        this.salt = salt;
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Set a master password: ");
        char[] masterPassword = scanner.nextLine().toCharArray();

        CryptoUtil cryptoUtil;
        byte[] salt;
        String verifier;

        try {
            // A fresh random salt each run means the derived key changes every
            // session; since passwordStore is in-memory only, this is fine —
            // there is nothing persisted that would need the same salt later.
            salt = CryptoUtil.generateSalt();
            cryptoUtil = new CryptoUtil(masterPassword, salt);
            verifier = cryptoUtil.createVerifier();
        } finally {
            Arrays.fill(masterPassword, '\0');
        }

        PasswordManager manager = new PasswordManager(cryptoUtil, salt);
        manager.verifier = verifier;

        while (true) {
            System.out.println("1. Add Password");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Load Vault File");
            System.out.println("4. Save to New Vault File");
            System.out.println("5. Delete Password");
            System.out.println("6. List Saved Sites");
            System.out.println("7. Exit");
            System.out.print("Choose an option: ");
            int choice=0;

            try 
            {
                choice = Integer.parseInt(scanner.nextLine().trim());
            } 
            catch (NumberFormatException e) 
            {
                System.out.println("Invalid input! Please enter a valid option number (1-7).\n");
                continue; // Restarts the loop to show the menu again
            }

            switch (choice) {
                case 1:
                    System.out.print("Enter site: ");
                    String site = scanner.nextLine();

                    boolean exists = manager.hasPassword(site);

                    if (exists) {
                        System.out.println("A password already exists for this site.");
                        System.out.print("Overwrite it? (y/N): ");
                        String response = scanner.nextLine();

                        if (!response.trim().equalsIgnoreCase("y")) {
                            System.out.println("Update cancelled.");
                            break;
                        }
                    }

                    System.out.print("Enter password: ");
                    String password = scanner.nextLine();

                    boolean added = manager.addPassword(site, password);

                    if (added) {
                        if (exists) {
                            System.out.println("Password updated successfully.");
                        } else {
                            System.out.println("Password added successfully.");
                        }
                    }

                    break;
                case 2:
                    System.out.print("Enter site: ");
                    site = scanner.nextLine();
                    String retrievedPassword = manager.getPassword(site);
                    System.out.println("Password: " + retrievedPassword);
                    break;
                case 3:
                    System.out.println("Enter file path: ");
                    String file = scanner.nextLine();
                    try {
                       LoadedVault loadedVault = manager.loadVaultFile(file);

                       while (true) {
                           System.out.print("Enter master password (press Enter to cancel): ");
                           char[] repeatMasterPassword = scanner.nextLine().toCharArray();

                           if (repeatMasterPassword.length == 0) {
                               System.out.println("Load cancelled.");
                               break;
                           }

                           try {
                               System.out.println("Deriving key...");
                               CryptoUtil testCrypto = new CryptoUtil(repeatMasterPassword, loadedVault.salt());

                               if (manager.verifier == null || testCrypto.verify(loadedVault.verifier())) {

                                   String newVerifier = loadedVault.verifier();

                                   if (newVerifier == null) {
                                       System.out.println("This vault has no password verification.");
                                       System.out.println("The password you just entered becomes the one it expects from now on.");
                                       newVerifier = testCrypto.createVerifier();
                                   }
                                   manager.salt = loadedVault.salt();
                                   manager.verifier = newVerifier;
                                   manager.passwordStore = loadedVault.passwordStore();
                                   manager.cryptoUtil = testCrypto;
                                   manager.vaultFile = file;
                                   System.out.println("Vault file loaded successfully");
                                   break;
                               }

                               System.out.println("Wrong master password. Try again.");
                           } finally {
                               Arrays.fill(repeatMasterPassword, '\0');
                           }
                       }
                    } catch (NullPointerException e) {
                        System.out.println("not a valid vault file");
                    } catch (Exception e) {
                        System.out.printf("failed to load vault file: %s\n", e.getMessage());
                    }
                    break;
                case 4:
                    System.out.println("Enter file path: ");
                    String newFile = scanner.nextLine();
                    try {
                        manager.saveVaultFile(newFile);
                        manager.vaultFile = newFile;
                        System.out.printf("Vault Saved Successfully at %s\n", newFile);
                    } catch (IOException e) {
                        System.out.printf("Failed to Save Vault: %s\n", e.getMessage());
                    }
                    break;
                case 5:
                    System.out.print("Enter site: ");
                    site = scanner.nextLine();
                    manager.deletePassword(site);
                    break;
                case 6:
                    manager.listSavedSites();
                    break;
                case 7:
                    System.exit(0);
                    break;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }

    public boolean hasPassword(String site) {
        return passwordStore.containsKey(site);
    }

    // Encrypts the password before storing it — the store never holds plaintext.
    public boolean addPassword(String site, String password) {
        try {
            passwordStore.put(site, cryptoUtil.encrypt(password));
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to encrypt password. Entry not saved.");
            return false;
        }

        if (this.vaultFile != null) {
            try {
                this.saveVaultFile(this.vaultFile);
            } catch (IOException e) {
                System.out.printf("Password stored, but failed to save to file: %s\n", e.getMessage());
                return false;
            }
        }

        return true;
    }

    public void deletePassword(String site) {
        if (passwordStore.containsKey(site)) {
            passwordStore.remove(site);
            System.out.println("Password deleted successfully.");

            if (this.vaultFile != null) {
                try {
                    this.saveVaultFile(this.vaultFile);
                } catch (IOException e) {
                    System.out.printf(
                        "Failed to save changes to file: %s\n",
                        e.getMessage()
                    );
                }
            }
        } else {
            System.out.println("No password found for this site.");
        }
    }

    public String getPassword(String site) {
        try {
            String encryptedPassword = passwordStore.get(site);
            return encryptedPassword != null ? cryptoUtil.decrypt(encryptedPassword) : "No password found for this site.";
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void listSavedSites() {
        if (passwordStore.isEmpty()) {
            System.out.println("No sites saved yet.");
        } else {
            System.out.println("Saved sites:");
            passwordStore.keySet()
                    .stream()
                    .sorted()
                    .forEach(site -> System.out.println("  " + site));
        }
    }

    private LoadedVault loadVaultFile(String filePath) throws Exception {
        Properties p = new Properties();
        try (var in = new FileInputStream(filePath)) {
            p.load(in);   
        }
        
        byte[] salt = Base64.getDecoder().decode((String) p.get("salt_value"));
        String verifier = (String) p.get("verifier");

        p.remove("salt_value");
        p.remove("verifier");
        Map<String, String> newPasswordStore = new HashMap<>();
        for (String item : p.stringPropertyNames()) {
            newPasswordStore.put(item, p.getProperty(item));
        }

        return new LoadedVault(salt, verifier, newPasswordStore);
    }

    private void saveVaultFile(String filePath) throws IOException {
        Properties pHashMap = new Properties();
        pHashMap.put("salt_value", Base64.getEncoder().encodeToString(this.salt));

        if (this.verifier != null) {
            pHashMap.put("verifier", this.verifier);
        }

        pHashMap.putAll(passwordStore);

        Path vaultPath = Path.of(filePath);
        restrictVaultFilePermissions(vaultPath);
        try (OutputStream out = Files.newOutputStream(vaultPath)) {
            pHashMap.store(out, "vault");
        }
    }

    private static void restrictVaultFilePermissions(Path vaultPath) throws IOException {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");

        try {
            try {
                Files.createFile(vaultPath, PosixFilePermissions.asFileAttribute(ownerOnly));
            } catch (FileAlreadyExistsException ignored) {
                // Existing vault files should still be tightened before rewriting.
            }
            Files.setPosixFilePermissions(vaultPath, ownerOnly);
        } catch (UnsupportedOperationException e) {
            restrictVaultFilePermissionsWithoutPosix(vaultPath);
        }
    }

    private static void restrictVaultFilePermissionsWithoutPosix(Path vaultPath) throws IOException {
        try {
            Files.createFile(vaultPath);
        } catch (FileAlreadyExistsException ignored) {
            // Existing vault files should still be tightened before rewriting.
        }

        File vaultFile = vaultPath.toFile();

        // Non-POSIX platforms such as Windows do not expose a true 0600 mode
        // through the File API. Apply the closest owner-only settings supported
        // by the runtime without failing the save when an operation is not
        // expressible on the current filesystem.
        vaultFile.setReadable(false, false);
        vaultFile.setWritable(false, false);
        vaultFile.setExecutable(false, false);
        vaultFile.setReadable(true, true);
        vaultFile.setWritable(true, true);
    }
}
