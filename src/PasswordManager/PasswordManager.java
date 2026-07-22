package PasswordManager;

import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class PasswordManager {
    private final CryptoUtil cryptoUtil;
    private Map<String, String> passwordStore = new HashMap<>();

    public PasswordManager(CryptoUtil cryptoUtil) {
        this.cryptoUtil = cryptoUtil;
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Set a master password: ");
        char[] masterPassword = scanner.nextLine().toCharArray();

        CryptoUtil cryptoUtil;

        try {
            // A fresh random salt each run means the derived key changes every
            // session; since passwordStore is in-memory only, this is fine —
            // there is nothing persisted that would need the same salt later.
            byte[] salt = CryptoUtil.generateSalt();
            cryptoUtil = new CryptoUtil(masterPassword, salt);
        } finally {
            java.util.Arrays.fill(masterPassword, '\0');
        }

        PasswordManager manager = new PasswordManager(cryptoUtil);
        while (true) {
            System.out.println("1. Add Password");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Exit");
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

    // Decrypts on read so the caller always gets the original plaintext back.
    public String getPassword(String site) {
        try {
            String encryptedPassword = passwordStore.get(site);
            return encryptedPassword != null ? cryptoUtil.decrypt(encryptedPassword) : "No password found for this site.";
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}