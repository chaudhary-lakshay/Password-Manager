package PasswordManager;

/*
 * Educational example of the Java AES API — NOT a real password manager.
 * The security flaws below are left in deliberately and labeled with FLAW:
 * comments; the README explains the production-grade fix for each.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class PasswordManager {
    private final CryptoUtil cryptoUtil;
    private Map<String, String> passwordStore = new HashMap<>();
    protected String vaultFile = null;


    public PasswordManager(CryptoUtil cryptoUtil) {
        this.cryptoUtil = cryptoUtil;
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

        PasswordManager manager = new PasswordManager(cryptoUtil);

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
                        System.out.println("Vault file loaded successfully");
                    } catch (IOException | ClassNotFoundException e) {
                        System.out.printf("Failed to load file: {}\n", e.getClass());
                    }
                    break;
                case 4:
                    System.out.println("Enter file path: ");
                    String newFile = scanner.nextLine();
                    try {
                        File f = new File(newFile);
                        f.createNewFile();
                        manager.vaultFile = newFile;
                        manager.saveVaultFile(manager.vaultFile);
                        System.out.println("Vault Saved Successfully");
                    } catch (IOException | NullPointerException e) {
                        System.out.printf("Failed to Save Vault: {}\n", e.getMessage());
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

    private void loadVaultFile(String filePath) throws IOException, ClassNotFoundException {

        try (FileInputStream fileIn = new FileInputStream(filePath);
            ObjectInputStream in = new ObjectInputStream(fileIn)) {
            this.passwordStore = (Map<String, String>) in.readObject();
    
        } catch (IOException | ClassNotFoundException e) {
            throw e;
        }
    }

    private void saveVaultFile(String filePath) throws IOException {
        try (FileOutputStream fileOut = new FileOutputStream(filePath);
            ObjectOutputStream out = new ObjectOutputStream(fileOut)) {
            out.writeObject(this.passwordStore);
        } catch (IOException e) {
            throw e;
        }
    }

    
}

