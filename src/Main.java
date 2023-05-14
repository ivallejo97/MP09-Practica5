import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.security.*;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        //1.1.1
        System.out.println("-------------------------------------------------------------------");
        System.out.println("Genera un parell de claus (KeyPair) de 1024bits, i utilitza-les per xifrar i desxifrar un missatge.\n");

        KeyPair keys = UtilitatsXifrar.randomGenerate(1024);
        String textoCifrado = "Hola mundo, 1.1.1";

        byte[] textoEncriptado = UtilitatsXifrar.encryptDataA5(textoCifrado.getBytes(), keys.getPublic());
        byte[] textoDesencriptado = UtilitatsXifrar.decryptDataA5(textoEncriptado, keys.getPrivate());

        String textoDescifrado = new String(textoDesencriptado, 0, textoDesencriptado.length);

        System.out.println("Mensaje cifrado: " + textoEncriptado);
        System.out.println("Mensjae descifrado: " + textoDescifrado);

        System.out.println("-------------------------------------------------------------------");

        //1.1.2
        System.out.println("1.1.2. Fes que el missatge a xifrar s'entra pel teclat.\n");

        KeyPair keys2 = UtilitatsXifrar.randomGenerate(1024);
        System.out.print("Escribe el texto a cifrar: ");
        String textoCifrado2 = scanner.nextLine();
        System.out.println();

        byte[] textoEncriptado2 = UtilitatsXifrar.encryptDataA5(textoCifrado2.getBytes(), keys2.getPublic());
        byte[] textoDesencriptado2 = UtilitatsXifrar.decryptDataA5(textoEncriptado2, keys2.getPrivate());

        String textoDescifrado2 = new String(textoDesencriptado2, 0, textoDesencriptado2.length);

        System.out.println("Mensaje cifrado: " + textoEncriptado2);
        System.out.println("Mensaje descifrado: " + textoDescifrado2);

        System.out.println("-------------------------------------------------------------------");

        //1.1.3
        System.out.println("1.1.3. Fes servir els mètodes get Public i getPrivate per obtenir les claus i el mètodes derivats d’aquestes claus i observa quines dades aporten.\n");

        System.out.println("Clave Publica: " + keys.getPublic().getAlgorithm() + " " + Arrays.toString(keys.getPublic().getEncoded()) + " " + keys.getPublic().getFormat());
        System.out.println("Clave Privada " + keys.getPrivate().getAlgorithm() + " " + Arrays.toString(keys.getPrivate().getEncoded()) + " " + keys.getPrivate().getFormat());

        System.out.println("-------------------------------------------------------------------");

        //1.2.1
        System.out.println("1.2.1. Fés la lectura d’un dels keystore que tinguis al teu sistema i extreu-ne la següent informació: \n");

        KeyStore keyStore = UtilitatsXifrar.loadKeyStore("C:/Users/ivall/keystore_ivan.jks","usuario");

        Enumeration<String> enumeration = keyStore.aliases();
        String alias = null;

        System.out.println("1. Tipus de keystore que és (JKS, JCEKS, PKCS12, ...): " + keyStore.getType() + "\n" +
                           "2. Mida del magatzem (quantes claus hi ha?): " + keyStore.size() + "\n");

        while (enumeration.hasMoreElements()) {
            alias = enumeration.nextElement();
            System.out.println("3. Àlies de totes les claus emmagatzemades: " + alias + "\n" +
                               "4. El certificat d’una de les claus: " + keyStore.getCertificate(alias) + "\n" +
                               "5. L'algoritme de xifrat d’alguna de les claus: "+ keyStore.getCertificate(alias));
        }

        System.out.println("-------------------------------------------------------------------");

        //1.2.2
        System.out.println("1.2.2. Crea una nova clau simètrica (SecretKey) i desa-la (setEntry) al keystore. Tingueu en compte que si deseu (mètode store) amb una altra contrasenya el \n" +
                "keystore queda modificat. Fes un captura de pantalla llistant amb la comanda keytool les claus del keystore on has fet la nova entrada.\n");

        SecretKey claveSecreta = UtilitatsXifrar.passwordKeyGeneration("BXJVRFSJZRZR9WE", 192);
        String password = "usuario";

        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password.toCharArray());
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(claveSecreta);

        FileOutputStream fileOutputStream = new FileOutputStream("C:/Users/ivall/keyEJ2.jks");
        keyStore.setEntry("mykey2", secretKeyEntry ,protectionParameter);
        keyStore.store(fileOutputStream,password.toCharArray());
        fileOutputStream.close();

        System.out.println("Clave guardada correctamente en la keystore");

        System.out.println("-------------------------------------------------------------------");

        //1.3
        System.out.println("1.3. Fes un funció que donat un fitxer amb un certificat (.cer) retorni la seva PublicKey. Usa aquesta funció i mostra per pantalla les dades de la PublicKey llegida. \n");

        String fichero = "C:/Users/ivall/Documents/certificadoExportado.cer";
        System.out.println("Ruta del fichero .cer --> " + fichero);

        PublicKey publicKey = UtilitatsXifrar.getPublicKey(fichero);
        System.out.println("Algoritmo de la clave: " + publicKey.getAlgorithm());
        System.out.println("Formato de la clave: " + publicKey.getFormat());
        System.out.println("Encoded de la clave: " + publicKey.getEncoded());

        System.out.println("-------------------------------------------------------------------");

        System.out.println("1.4. Llegir una clau asimètrica del keystore i extreure’n la PublicKey. Imprimir-la per pantalla. Podeu crear una funció igual que en el punt 3 fent sobrecàrrega) \n");

        String rutaKeyStore = "C:/Users/ivall/Documents/keystore_ivan.jks";
        System.out.println("Ruta del KeyStore --> " + rutaKeyStore);

        String aliasCertificado = "lamevaclauM9";
        System.out.println("Alias del certificado --> " + aliasCertificado);

        System.out.print("Introduce la contraseña del Keystore: ");
        String passwordKeyStore = scanner.nextLine();

        System.out.print("Introduce la contraseña de la clave: ");
        String passwordClave = scanner.nextLine();

        KeyStore keyStore1 = UtilitatsXifrar.loadKeyStore(rutaKeyStore, passwordKeyStore);
        PublicKey publicKey2 = UtilitatsXifrar.getPublicKey(keyStore1, aliasCertificado, passwordClave);

        System.out.println("Algoritmo de la clave: " + publicKey2.getAlgorithm());
        System.out.println("Formato de la clave: " + publicKey2.getFormat());
        System.out.println("Encoded de la clave: " + publicKey2.getEncoded());

        System.out.println("-------------------------------------------------------------------");

        //1.5
        System.out.println("1.5. Fer un funció que donades unes dades i una PrivateKey retorni la signatura. Usa-la i mostra la signatura per pantalla. (funció dels apunts 1.3.1) \n");

        String texoCifrado3 = "Hola mundo, 1.5";
        byte[] firma = UtilitatsXifrar.signData(texoCifrado3.getBytes(), keys.getPrivate());

        System.out.println("Firma: " + Arrays.toString(firma));

        System.out.println("-------------------------------------------------------------------");

        //EXERCICI 1.6
        System.out.println("1.6. Fer una funció que donades unes dades, una signatura i la PublicKey, comprovi la validesa de la informació. (funció dels apunts 1.3.2) \n");

        String textoCifrado4 = "Hola mundo, 1.6";

        byte[] firma2 = UtilitatsXifrar.signData(texoCifrado3.getBytes(), keys.getPrivate());
        System.out.println( "La valideza de la información és: " + UtilitatsXifrar.validateSignature(textoCifrado4.getBytes(), firma2, keys.getPublic()));

        System.out.println("-------------------------------------------------------------------");

        //EXERCICI 2.2
        System.out.println("2.2. Genereu un parell de claus (KeyPair) i proveu de xifrar i desxifrar un text amb clau embolcallada.\n");

        String textoCifrado5 = "Hola mundo, 2.2";
        byte[][] textoEncriptado3 = UtilitatsXifrar.encryptWrappedData(textoCifrado5.getBytes(), keys.getPublic());

        byte[] textoDesencriptado3 = UtilitatsXifrar.decryptWrappedData(textoEncriptado3, keys.getPrivate());
        String textoDescifrado4 = new String(textoDesencriptado3,0, textoDesencriptado3.length);
        System.out.println(textoDescifrado4);

        System.out.println("-------------------------------------------------------------------");

    }
}