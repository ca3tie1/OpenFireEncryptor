package com.castiel;

import org.apache.commons.cli.*;

public class OpenFireEncryptor {
    private static HelpFormatter helpFormatter = new HelpFormatter();
    private static Options options = new Options();
    private static CommandLine commandLine = null;
    private static String method = "Decrypt";
    private static String type = "AES";
    private static String encStr = null;
    private static String keyStr = null;
    private static Encryptor propertyEncryptor;
    private static CommandLineParser parser = new BasicParser();

    public static void main(String[] args) {

        // 解析命令行参数
        parseCommandLine();

        try {
            commandLine = parser.parse( options, args );
        } catch (ParseException e) {
            printHelp();
        }

        if (commandLine.hasOption("h") || ! commandLine.hasOption("s")) {
            printHelp();
        }

        if (commandLine.hasOption("m"))
            method = commandLine.getOptionValue("m");

        if (commandLine.hasOption("t"))
            type = commandLine.getOptionValue("t");

        if (commandLine.hasOption("k"))
            keyStr = commandLine.getOptionValue("k");

        encStr = commandLine.getOptionValue("s");

        if ("AES".equals(type.toUpperCase())) {
            propertyEncryptor = new AesEncryptor(keyStr);
        } else {
            propertyEncryptor = new Blowfish(keyStr);
        }

        if ("ENCRYPT".equals(method.toUpperCase())) {
            System.out.println(propertyEncryptor.encrypt(encStr));
        } else {
            System.out.println(propertyEncryptor.decrypt(encStr));
        }
    }

    public static void printHelp() {
        helpFormatter.printHelp("OpenFireEncryptor",options);
        System.exit(0);
    }

    public static void parseCommandLine() {
        options.addOption("h", "help",false, "Help text");
        options.addOption("m", "method", true,"Method of Encryptor(e.g:Encrypt or Decrypt,default Decrypt)" );
        options.addOption("t","type",true,"The type of encryptor(AES or Blowfish,default AES)");
        options.addOption("s", "string", true, "The string for encrypt or decrypt");
        options.addOption("k", "key", true, "The key for encryptor,default null");
    }
}
