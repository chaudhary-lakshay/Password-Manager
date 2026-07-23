package PasswordManager;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;

public class PasswordManager {
    private CryptoUtil cryptoUtil;
    private Map<String, String> passwordStore = new HashMap<>();
    protected String vaultFile = null;
    protected byte[] salt = null;


    public PasswordManager(CryptoUtil cryptoUtil, byte[] salt) {
        this.cryptoUtil = cryptoUtil;
        this.salt = salt;
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Set a master password: ");
        char[] masterPassword = scanner.nextLine().toCharArray();

        // A fresh random salt each run means the derived key changes every
        // session; since passwordStore is in-memory only, this is fine —
        // there is nothing persisted that would need the same salt later.
        byte[] salt = CryptoUtil.generateSalt();
        CryptoUtil cryptoUtil = new CryptoUtil(masterPassword, salt);

        PasswordManager manager = new PasswordManager(cryptoUtil, salt);

        while (true) {
            System.out.println("1. Add Password");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Load Vault File");
            System.out.println("4. Save to New Vault File");
            System.out.println("5. Exit");
            System.out.print("Choose an option: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // consume newline

            switch (choice) {
                case 1:
                    System.out.print("Enter site: ");
                    String site = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String password = scanner.nextLine();
                    manager.addPassword(site, password);
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
                        manager.loadVaultFile(file);
                        manager.vaultFile = file;
                        System.out.println("Vault file loaded successfully");

                        System.out.print("Enter master password: ");
                        char[] repeatMasterPassword = scanner.nextLine().toCharArray();

                        manager.cryptoUtil = new CryptoUtil(repeatMasterPassword, manager.salt);
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
                    System.exit(0);
                    break;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }

    // Encrypts the password before storing it — the store never holds plaintext.
    public void addPassword(String site, String password) {
        try {
            String encryptedPassword = cryptoUtil.encrypt(password);
            passwordStore.put(site, encryptedPassword);
            System.out.println("Password added successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (this.vaultFile != null) {
            try {
                this.saveVaultFile(this.vaultFile);
            } catch (IOException e) {
                System.out.printf("Failed to save changes to file: %s\n", e.getMessage());
            }
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

    private void loadVaultFile(String filePath) throws Exception {
        Properties p = new Properties();
        try (var in = new FileInputStream(filePath)) {
            p.load(in);   
        }
        
        this.salt = Base64.getDecoder().decode((String) p.get("salt_value"));
        p.remove("salt_value");// Remove salt value so it isn't added to hashmap

        Map<String, String> newPasswordStore = new HashMap<>();
        for (String item : p.stringPropertyNames()) {
            newPasswordStore.put(item, p.getProperty(item));
        }

        this.passwordStore = newPasswordStore;
    }

    private void saveVaultFile(String filePath) throws IOException {
        Properties pHashMap = new Properties();
        pHashMap.put("salt_value", Base64.getEncoder().encodeToString(this.salt));
        pHashMap.putAll(passwordStore);

        // TODO: Restrict file permissions
        try (var out = new FileOutputStream(filePath)) {
            pHashMap.store(out, "vault");
        }
    }

    
}

