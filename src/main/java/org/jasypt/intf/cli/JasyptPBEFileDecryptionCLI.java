/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.jasypt.intf.cli;

import java.util.Properties;

import org.jasypt.util.filehandler.AssignHandler;
import org.jasypt.util.filehandler.FileHandler;
import org.jasypt.util.filehandler.SimpleHandler;


/**
 * <p>
 * This class supports the CLI "encrypt" operation where input is from a file.
 * </p>
 * <p>
 * <b>It should NEVER be used inside your code, only from the supplied
 * command-line tools</b>.
 * </p>
 * 
 * @since 1.10
 * 
 * @author Prakash Tiwari
 *
 */
public final class JasyptPBEFileDecryptionCLI {
    
    /*
     * The required arguments for this CLI operation.
     */
    private static final String[][] VALID_REQUIRED_ARGUMENTS =
        new String[][] {
            new String [] {
                ArgumentNaming.ARG_INPUTFILE
            },
    		new String [] {
                ArgumentNaming.ARG_PASSWORD
            }
        };
    
    /*
     * The optional arguments for this CLI operation.
     */
    private static final String[][] VALID_OPTIONAL_ARGUMENTS =
        new String[][] {
    	new String [] {
                ArgumentNaming.ARG_DELIMITER
            },
            new String [] {
                ArgumentNaming.ARG_VERBOSE
            },
            new String [] {
                ArgumentNaming.ARG_ALGORITHM
            },
            new String [] {
                ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS
            },
            new String [] {
                ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME
            },
            new String [] {
                ArgumentNaming.ARG_PROVIDER_NAME
            },
            new String [] {
                ArgumentNaming.ARG_PROVIDER_CLASS_NAME
            },
            new String [] {
                ArgumentNaming.ARG_STRING_OUTPUT_TYPE
            }
        };
    
    
    /**
     * <p>
     * CLI execution method.
     * </p>
     * 
     * @param args the command execution arguments
     */
    public static void main(final String[] args) {

        final boolean verbose = CLIUtils.getVerbosity(args);

        try {
            
            String applicationName = null;
            String[] arguments = null;
            if (args[0] == null || args[0].indexOf("=") != -1) {
                applicationName = JasyptPBEStringEncryptionCLI.class.getName();
                arguments = args;
            } else {
                applicationName = args[0];
                arguments = new String[args.length - 1];
                System.arraycopy(args, 1, arguments, 0, args.length - 1);
            }
            
            final Properties argumentValues = 
                CLIUtils.getArgumentValues(
                        applicationName, arguments, 
                        VALID_REQUIRED_ARGUMENTS, VALID_OPTIONAL_ARGUMENTS);

            CLIUtils.showEnvironment(verbose);

            final String inputFile = argumentValues.getProperty(ArgumentNaming.ARG_INPUTFILE);
            
            CLIUtils.showArgumentDescription(argumentValues, verbose);
            
            final FileHandler handler;
            final String outputPath;
            
            if(argumentValues.containsKey("delimiter")) {
            	handler = AssignHandler.assign(argumentValues);
            	outputPath = handler.decryptFile(inputFile, argumentValues);
            }
            else {
            	handler = new SimpleHandler();
            	outputPath = handler.decryptFile(inputFile, argumentValues);
            }
            
            if (outputPath != null) {
            	String output = "The decrypted values are written in: " + outputPath;
            	CLIUtils.showOutput(output, verbose);
            }

        } catch (Throwable t) {
            CLIUtils.showError(t, verbose);
        }
        
    }
    
    
    /*
     * Instantiation is forbidden.
     */
    private JasyptPBEFileDecryptionCLI() {
        super();
    }
    
}
