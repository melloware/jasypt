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
package org.jasypt.encryption.pbe;

import java.security.InvalidKeyException;
import java.security.Provider;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.config.PBECleanablePasswordConfig;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.AlreadyInitializedException;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.normalization.Normalizer;
import org.jasypt.salt.FixedSaltGenerator;
import org.jasypt.salt.IVGenerator;
import org.jasypt.salt.RandomIVGenerator;
import org.jasypt.salt.RandomSaltGenerator;
import org.jasypt.salt.SaltGenerator;

/**
 * <p>
 * Standard implementation of the {@link PBEByteEncryptor} interface. This class lets the user specify the algorithm
 * (and provider) to be used for encryption, the password to use, the number of hashing iterations and the salt
 * generator that will be applied for obtaining the encryption key.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * <p>
 * <br/>
 * <b><u>Configuration</u></b>
 * </p>
 * <p>
 * The algorithm, provider, password, key-obtention iterations and salt generator can take values in any of these ways:
 * <ul>
 * <li>Using its default values (except for password).</li>
 * <li>Setting a <tt>{@link org.jasypt.encryption.pbe.config.PBEConfig}</tt> object which provides new configuration
 * values.</li>
 * <li>Calling the corresponding <tt>setAlgorithm(...)</tt>, <tt>setProvider(...)</tt>, <tt>setProviderName(...)</tt>,
 * <tt>setPassword(...)</tt>, <tt>setKeyObtentionIterations(...)</tt> or <tt>setSaltGenerator(...)</tt> methods.</li>
 * </ul>
 * And the actual values to be used for initialization will be established by applying the following priorities:
 * <ol>
 * <li>First, the default values are considered (except for password).</li>
 * <li>Then, if a <tt>{@link org.jasypt.encryption.pbe.config.PBEConfig}</tt> object has been set with
 * <tt>setConfig(...)</tt>, the non-null values returned by its <tt>getX()</tt> methods override the default
 * values.</li>
 * <li>Finally, if the corresponding <tt>setX(...)</tt> method has been called on the encryptor itself for any of the
 * configuration parameters, the values set by these calls override all of the above.</li>
 * </ol>
 * </p>
 * <p>
 * <br/>
 * <b><u>Initialization</u></b>
 * </p>
 * <p>
 * Before it is ready to encrypt, an object of this class has to be <i>initialized</i>. Initialization happens:
 * <ul>
 * <li>When <tt>initialize()</tt> is called.</li>
 * <li>When <tt>encrypt(...)</tt> or <tt>decrypt(...)</tt> are called for the first time, if <tt>initialize()</tt> has
 * not been called before.</li>
 * </ul>
 * Once an encryptor has been initialized, trying to change its configuration will result in an
 * <tt>AlreadyInitializedException</tt> being thrown.
 * </p>
 * <p>
 * <br/>
 * <b><u>Usage</u></b>
 * </p>
 * <p>
 * An encryptor may be used for:
 * <ul>
 * <li><i>Encrypting messages</i>, by calling the <tt>encrypt(...)</tt> method.</li>
 * <li><i>Decrypting messages</i>, by calling the <tt>decrypt(...)</tt> method.</li>
 * </ul>
 * <b>If a random salt generator is used, two encryption results for the same message will always be different (except
 * in the case of random salt coincidence)</b>. This may enforce security by difficulting brute force attacks on sets of
 * data at a time and forcing attackers to perform a brute force attack on each separate piece of encrypted data.
 * </p>
 * <p>
 * To learn more about the mechanisms involved in encryption, read
 * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" target="_blank">PKCS &#035;5: Password-Based
 * Cryptography Standard</a>.
 * </p>
 *
 * @since 1.0
 * @author Daniel Fern&aacute;ndez
 */
public final class StandardPBEByteEncryptor implements PBEByteCleanablePasswordEncryptor {

    /**
     * The default algorithm to be used if none specified: PBEWithMD5AndDES.
     */
    public static final String DEFAULT_ALGORITHM = "PBEWithMD5AndDES";

    /**
     * The default number of hashing iterations applied for obtaining the encryption key from the specified password,
     * set to 1000.
     */
    public static final int DEFAULT_KEY_OBTENTION_ITERATIONS = 1000;

    /**
     * The default salt size, only used if the chosen encryption algorithm is not a block algorithm and thus block size
     * cannot be used as salt size.
     */
    public static final int DEFAULT_SALT_SIZE_BYTES = 8;

    /**
     * The default IV size
     */
    public static final int IV_SIZE_IN_BITS = 128;

    // Algorithm (and provider-related info) for Password Based Encoding.
    private String algorithm = DEFAULT_ALGORITHM;
    private String providerName = null;
    private Provider provider = null;

    // Password to be applied. This will NOT have a default value. If none
    // is set during configuration, an exception will be thrown.
    private char[] password = null;

    // Number of hashing iterations to be applied for obtaining the encryption
    // key from the specified password.
    private int keyObtentionIterations = DEFAULT_KEY_OBTENTION_ITERATIONS;

    // SaltGenerator to be used. Initialization of a salt generator is costly,
    // and so default value will be applied only in initialize(), if it finally
    // becomes necessary.
    private SaltGenerator saltGenerator = null;

    // IVGenerator to initialise IV
    private IVGenerator ivGenerator = null;

    // Size in bytes of the IV to be used
    private final int IVSizeBytes = IV_SIZE_IN_BITS;

    // Size in bytes of the salt to be used for obtaining the
    // encryption key. This size will depend on the PBE algorithm being used,
    // and it will be set to the size of the block for the specific
    // chosen algorithm (if the algorithm is not a block algorithm, the
    // default value will be used).
    private int saltSizeBytes = DEFAULT_SALT_SIZE_BYTES;

    // Config object set (optionally).
    private PBEConfig config = null;

    /*
     * Set of booleans which indicate whether the config or default values have to be overriden because of the setX
     * methods having been called.
     */
    private boolean algorithmSet = false;
    private boolean passwordSet = false;
    private boolean iterationsSet = false;
    private boolean saltGeneratorSet = false;
    private boolean providerNameSet = false;
    private boolean providerSet = false;
    private boolean ivGeneratorSet = false;

    /*
     * Flag which indicates whether the encryptor has been initialized or not. Once initialized, no further
     * modifications to its configuration will be allowed.
     */
    private boolean initialized = false;

    // Encryption key generated.
    private SecretKey key = null;

    // Ciphers to be used for encryption and decryption.
    private Cipher encryptCipher = null;
    private Cipher decryptCipher = null;

    // Flag which indicates whether the salt generator being used is a
    // FixedSaltGenerator implementation (in which case some optimizations can
    // be applied).
    private boolean usingFixedSalt = false;
    private byte[] fixedSaltInUse = null;

    /**
     * Creates a new instance of <tt>StandardPBEByteEncryptor</tt>.
     */
    public StandardPBEByteEncryptor() {
        super();
    }

    /**
     * <p>
     * Sets a <tt>{@link org.jasypt.encryption.pbe.config.PBEConfig}</tt> object for the encryptor. If this config
     * object is set, it will be asked values for:
     * </p>
     * <ul>
     * <li>Algorithm</li>
     * <li>Security Provider (or provider name)</li>
     * <li>Password</li>
     * <li>Hashing iterations for obtaining the encryption key</li>
     * <li>Salt generator</li>
     * </ul>
     * <p>
     * The non-null values it returns will override the default ones, <i>and will be overriden by any values specified
     * with a <tt>setX</tt> method</i>.
     * </p>
     *
     * @param config the <tt>PBEConfig</tt> object to be used as the source for configuration parameters.
     */
    public synchronized void setConfig(final PBEConfig config) {
        CommonUtils.validateNotNull(config, "Config cannot be set null");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.config = config;
    }

    /**
     * <p>
     * Sets the algorithm to be used for encryption, like <tt>PBEWithMD5AndDES</tt>.
     * </p>
     * <p>
     * This algorithm has to be supported by your JCE provider (if you specify one, or the default JVM provider if you
     * don't) and, if it is supported, you can also specify <i>mode</i> and <i>padding</i> for it, like
     * <tt>ALGORITHM/MODE/PADDING</tt>.
     * </p>
     *
     * @param algorithm the name of the algorithm to be used.
     */
    public synchronized void setAlgorithm(final String algorithm) {
        CommonUtils.validateNotEmpty(algorithm, "Algorithm cannot be set empty");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.algorithm = algorithm;
        algorithmSet = true;
    }

    /**
     * <p>
     * Sets the password to be used.
     * </p>
     * <p>
     * <b>There is no default value for password</b>, so not setting this parameter either from a
     * {@link org.jasypt.encryption.pbe.config.PBEConfig} object or from a call to <tt>setPassword</tt> will result in
     * an EncryptionInitializationException being thrown during initialization.
     * </p>
     *
     * @param password the password to be used.
     */
    @Override
    public synchronized void setPassword(final String password) {
        CommonUtils.validateNotEmpty(password, "Password cannot be set empty");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        if (this.password != null) {
            // We clean the old password, if there is one.
            cleanPassword(this.password);
        }
        this.password = password.toCharArray();
        passwordSet = true;
    }

    /**
     * <p>
     * Sets the password to be used, as a char[].
     * </p>
     * <p>
     * This allows the password to be specified as a <i>cleanable</i> char[] instead of a String, in extreme security
     * conscious environments in which no copy of the password as an immutable String should be kept in memory.
     * </p>
     * <p>
     * <b>Important</b>: the array specified as a parameter WILL BE COPIED in order to be stored as encryptor
     * configuration. The caller of this method will therefore be responsible for its cleaning (jasypt will only clean
     * the internally stored copy).
     * </p>
     * <p>
     * <b>There is no default value for password</b>, so not setting this parameter either from a
     * {@link org.jasypt.encryption.pbe.config.PBEConfig} object or from a call to <tt>setPassword</tt> will result in
     * an EncryptionInitializationException being thrown during initialization.
     * </p>
     *
     * @since 1.8
     * @param password the password to be used.
     */
    @Override
    public synchronized void setPasswordCharArray(final char[] password) {
        CommonUtils.validateNotNull(password, "Password cannot be set null");
        CommonUtils.validateIsTrue(password.length > 0, "Password cannot be set empty");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        if (this.password != null) {
            // We clean the old password, if there is one.
            cleanPassword(this.password);
        }
        this.password = new char[password.length];
        System.arraycopy(password, 0, this.password, 0, password.length);
        passwordSet = true;
    }

    /**
     * <p>
     * Set the number of hashing iterations applied to obtain the encryption key.
     * </p>
     * <p>
     * This mechanism is explained in <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" target="_blank">PKCS
     * &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     *
     * @param keyObtentionIterations the number of iterations
     */
    public synchronized void setKeyObtentionIterations(final int keyObtentionIterations) {
        CommonUtils.validateIsTrue(keyObtentionIterations > 0,
                    "Number of iterations for key obtention must be " + "greater than zero");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.keyObtentionIterations = keyObtentionIterations;
        iterationsSet = true;
    }

    /**
     * <p>
     * Sets the salt generator to be used. If no salt generator is specified, an instance of
     * {@link org.jasypt.salt.RandomSaltGenerator} will be used.
     * </p>
     *
     * @param saltGenerator the salt generator to be used.
     */
    public synchronized void setSaltGenerator(final SaltGenerator saltGenerator) {
        CommonUtils.validateNotNull(saltGenerator, "Salt generator cannot be set null");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.saltGenerator = saltGenerator;
        saltGeneratorSet = true;
    }

    /**
     * <p>
     * Sets the IV generator to be used. If no IV generator is specified, an instance of
     * {@link org.jasypt.salt.RandomIVGenerator} will be used.
     * </p>
     *
     * @param ivGenerator the IV generator to be used.
     */
    public synchronized void setIvGenerator(final IVGenerator ivGenerator) {
        CommonUtils.validateNotNull(ivGenerator, "IV generator cannot be set null");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.ivGenerator = ivGenerator;
        ivGeneratorSet = true;
    }

    /**
     * <p>
     * Sets the name of the security provider to be asked for the encryption algorithm. This security provider has to be
     * registered beforehand at the JVM security framework.
     * </p>
     * <p>
     * The provider can also be set with the {@link #setProvider(Provider)} method, in which case it will not be
     * necessary neither registering the provider beforehand, nor calling this {@link #setProviderName(String)} method
     * to specify a provider name.
     * </p>
     * <p>
     * Note that a call to {@link #setProvider(Provider)} overrides any value set by this method.
     * </p>
     * <p>
     * If no provider name / provider is explicitly set, the default JVM provider will be used.
     * </p>
     *
     * @since 1.3
     * @param providerName the name of the security provider to be asked for the encryption algorithm.
     */
    public synchronized void setProviderName(final String providerName) {
        CommonUtils.validateNotNull(providerName, "Provider name cannot be set null");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.providerName = providerName;
        providerNameSet = true;
    }

    /**
     * <p>
     * Sets the security provider to be asked for the encryption algorithm. The provider does not have to be registered
     * at the security infrastructure beforehand, and its being used here will not result in its being registered.
     * </p>
     * <p>
     * If this method is called, calling {@link #setProviderName(String)} becomes unnecessary.
     * </p>
     * <p>
     * If no provider name / provider is explicitly set, the default JVM provider will be used.
     * </p>
     *
     * @since 1.3
     * @param provider the provider to be asked for the chosen algorithm
     */
    public synchronized void setProvider(final Provider provider) {
        CommonUtils.validateNotNull(provider, "Provider cannot be set null");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.provider = provider;
        providerSet = true;
    }

    /*
     * Clone this encryptor 'size' times and initialize it. This encryptor will be at position 0 itself. Clones will NOT
     * be initialized.
     */
    synchronized StandardPBEByteEncryptor[] cloneAndInitializeEncryptor(final int size) {

        if (isInitialized()) {
            throw new EncryptionInitializationException("Cannot clone encryptor if it has been already initialized");
        }

        // If there is a config object, this forces the password configured value
        // (if any) into the this.password property.
        resolveConfigurationPassword();

        final char[] copiedPassword = new char[password.length];
        System.arraycopy(password, 0, copiedPassword, 0, password.length);

        // Initialize the encryptor - note that this will clean the
        // password (that's why copied it before)
        initialize();

        final StandardPBEByteEncryptor[] clones = new StandardPBEByteEncryptor[size];

        clones[0] = this;

        for (int i = 1; i < size; i++) {

            final StandardPBEByteEncryptor clone = new StandardPBEByteEncryptor();
            clone.setPasswordCharArray(copiedPassword);
            if (CommonUtils.isNotEmpty(algorithm)) {
                clone.setAlgorithm(algorithm);
            }
            clone.setKeyObtentionIterations(keyObtentionIterations);

            if (provider != null) {
                clone.setProvider(provider);
            }

            if (providerName != null) {
                clone.setProviderName(providerName);
            }

            if (saltGenerator != null) {
                clone.setSaltGenerator(saltGenerator);
            }

            if (ivGenerator != null) {
                clone.setIvGenerator(ivGenerator);
            }

            clones[i] = clone;

        }

        cleanPassword(copiedPassword);

        return clones;

    }

    /**
     * <p>
     * Returns true if the encryptor has already been initialized, false if not.<br/>
     * Initialization happens:
     * </p>
     * <ul>
     * <li>When <tt>initialize</tt> is called.</li>
     * <li>When <tt>encrypt</tt> or <tt>decrypt</tt> are called for the first time, if <tt>initialize</tt> has not been
     * called before.</li>
     * </ul>
     * <p>
     * Once an encryptor has been initialized, trying to change its configuration will result in an
     * <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     *
     * @return true if the encryptor has already been initialized, false if not.
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * <p>
     * Initialize the encryptor.
     * </p>
     * <p>
     * This operation will consist in determining the actual configuration values to be used, and then initializing the
     * encryptor with them. <br/>
     * These values are decided by applying the following priorities:
     * </p>
     * <ol>
     * <li>First, the default values are considered (except for password).</li>
     * <li>Then, if a <tt>{@link org.jasypt.encryption.pbe.config.PBEConfig}</tt> object has been set with
     * <tt>setConfig</tt>, the non-null values returned by its <tt>getX</tt> methods override the default values.</li>
     * <li>Finally, if the corresponding <tt>setX</tt> method has been called on the encryptor itself for any of the
     * configuration parameters, the values set by these calls override all of the above.</li>
     * </ol>
     * <p>
     * Once an encryptor has been initialized, trying to change its configuration will result in an
     * <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     *
     * @throws EncryptionInitializationException if initialization could not be correctly done (for example, no password
     *             has been set).
     */
    public synchronized void initialize() {

        // Double-check to avoid synchronization issues
        if (!initialized) {

            /*
             * If a PBEConfig object has been set, we need to consider the values it returns (if, for each value, the
             * corresponding "setX" method has not been called).
             */
            if (config != null) {

                resolveConfigurationPassword();

                final String configAlgorithm = config.getAlgorithm();
                if (configAlgorithm != null) {
                    CommonUtils.validateNotEmpty(configAlgorithm, "Algorithm cannot be set empty");
                }

                final Integer configKeyObtentionIterations = config.getKeyObtentionIterations();
                if (configKeyObtentionIterations != null) {
                    CommonUtils.validateIsTrue(configKeyObtentionIterations.intValue() > 0,
                                "Number of iterations for key obtention must be " + "greater than zero");
                }

                final SaltGenerator configSaltGenerator = config.getSaltGenerator();
                final IVGenerator configIVGenerator = config.getIVGenerator();

                final String configProviderName = config.getProviderName();
                if (configProviderName != null) {
                    CommonUtils.validateNotEmpty(configProviderName, "Provider name cannot be empty");
                }

                final Provider configProvider = config.getProvider();

                algorithm = algorithmSet || configAlgorithm == null ? algorithm : configAlgorithm;

                keyObtentionIterations = iterationsSet || configKeyObtentionIterations == null ? keyObtentionIterations
                            : configKeyObtentionIterations.intValue();

                saltGenerator = saltGeneratorSet || configSaltGenerator == null ? saltGenerator : configSaltGenerator;

                ivGenerator = ivGeneratorSet || configIVGenerator == null ? ivGenerator : configIVGenerator;

                providerName = providerNameSet || configProviderName == null ? providerName : configProviderName;

                provider = providerSet || configProvider == null ? provider : configProvider;

            }

            /*
             * If the encryptor was not set a salt generator in any way, it is time to apply its default value.
             */
            if (saltGenerator == null) {
                saltGenerator = new RandomSaltGenerator();
            }

            if (ivGenerator == null) {
                ivGenerator = new RandomIVGenerator();
            }

            try {

                // Password cannot be null.
                if (password == null) {
                    throw new EncryptionInitializationException("Password not set for Password Based Encryptor");
                }

                // Normalize password to NFC form
                final char[] normalizedPassword = Normalizer.normalizeToNfc(password);

                /*
                 * Encryption and decryption Ciphers are created the usual way.
                 */
                final PBEKeySpec pbeKeySpec = new PBEKeySpec(normalizedPassword);

                // We don't need the char[] passwords anymore -> clean!
                cleanPassword(password);
                cleanPassword(normalizedPassword);

                if (provider != null) {

                    final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, provider);

                    key = factory.generateSecret(pbeKeySpec);

                    encryptCipher = Cipher.getInstance(algorithm, provider);
                    decryptCipher = Cipher.getInstance(algorithm, provider);

                }
                else if (providerName != null) {

                    final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, providerName);

                    key = factory.generateSecret(pbeKeySpec);

                    encryptCipher = Cipher.getInstance(algorithm, providerName);
                    decryptCipher = Cipher.getInstance(algorithm, providerName);

                }
                else {

                    final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);

                    key = factory.generateSecret(pbeKeySpec);

                    encryptCipher = Cipher.getInstance(algorithm);
                    decryptCipher = Cipher.getInstance(algorithm);

                }

            }
            catch (final EncryptionInitializationException e) {
                throw e;
            }
            catch (final Throwable t) {
                throw new EncryptionInitializationException(t);
            }

            // The salt size for the chosen algorithm is set to be equal
            // to the algorithm's block size (if it is a block algorithm).
            final int algorithmBlockSize = encryptCipher.getBlockSize();
            if (algorithmBlockSize > 0) {
                saltSizeBytes = algorithmBlockSize;
            }

            usingFixedSalt = saltGenerator instanceof FixedSaltGenerator;

            if (usingFixedSalt) {

                // Create salt
                fixedSaltInUse = saltGenerator.generateSalt(saltSizeBytes);

                // Generate the IV
                final byte[] iv = ivGenerator.generateIV(IVSizeBytes);

                /*
                 * Initialize the Cipher objects themselves. Due to the fact that we will be using a fixed salt, this
                 * can be done just once, which means a better performance at the encrypt/decrypt methods.
                 */

                IvParameterSpec ivParameterSpec = null;
                if (iv != null) {
                    ivParameterSpec = new IvParameterSpec(iv);
                }

                final PBEParameterSpec parameterSpec = new PBEParameterSpec(fixedSaltInUse, keyObtentionIterations,
                            ivParameterSpec);

                try {

                    encryptCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
                    decryptCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

                }
                catch (final Exception e) {
                    // If encryption fails, it is more secure not to return any
                    // information about the cause in nested exceptions. Simply fail.
                    throw new EncryptionOperationNotPossibleException();
                }

            }

            initialized = true;

        }

    }

    private synchronized void resolveConfigurationPassword() {

        // Double-check to avoid synchronization issues
        if (!initialized) {

            if (config != null && !passwordSet) {

                // Get the configured password. If the config object implements
                // CleanablePassword, we get password directly as a char array
                // in order to avoid unnecessary creation of immutable Strings
                // containing such password.
                char[] configPassword = null;
                if (config instanceof PBECleanablePasswordConfig) {
                    configPassword = ((PBECleanablePasswordConfig) config).getPasswordCharArray();
                }
                else {
                    final String configPwd = config.getPassword();
                    if (configPwd != null) {
                        configPassword = configPwd.toCharArray();
                    }
                }

                if (configPassword != null) {
                    CommonUtils.validateIsTrue(configPassword.length > 0, "Password cannot be set empty");
                }

                if (configPassword != null) {
                    password = new char[configPassword.length];
                    System.arraycopy(configPassword, 0, password, 0, configPassword.length);
                    passwordSet = true;
                    cleanPassword(configPassword);
                }

                // Finally, clean the password at the configuration object
                if (config instanceof PBECleanablePasswordConfig) {
                    ((PBECleanablePasswordConfig) config).cleanPassword();
                }

            }

        }

    }

    private static void cleanPassword(final char[] password) {
        if (password != null) {
            synchronized (password) {
                final int pwdLength = password.length;
                for (int i = 0; i < pwdLength; i++) {
                    password[i] = (char) 0;
                }
            }
        }
    }

    /**
     * <p>
     * Encrypts a message using the specified configuration.
     * </p>
     * <p>
     * The mechanisms applied to perform the encryption operation are described in
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" target="_blank">PKCS &#035;5: Password-Based
     * Cryptography Standard</a>.
     * </p>
     * <p>
     * This encryptor uses a salt for each encryption operation. The size of the salt depends on the algorithm being
     * used. This salt is used for creating the encryption key and, if generated by a random generator, it is also
     * appended unencrypted at the beginning of the results so that a decryption operation can be performed.
     * </p>
     * <p>
     * <b>If a random salt generator is used, two encryption results for the same message will always be different
     * (except in the case of random salt coincidence)</b>. This may enforce security by difficulting brute force
     * attacks on sets of data at a time and forcing attackers to perform a brute force attack on each separate piece of
     * encrypted data.
     * </p>
     *
     * @param message the byte array message to be encrypted
     * @return the result of encryption
     * @throws EncryptionOperationNotPossibleException if the encryption operation fails, ommitting any further
     *             information about the cause for security reasons.
     * @throws EncryptionInitializationException if initialization could not be correctly done (for example, no password
     *             has been set).
     */
    @Override
    public byte[] encrypt(final byte[] message) throws EncryptionOperationNotPossibleException {

        if (message == null) {
            return null;
        }

        // Check initialization
        if (!isInitialized()) {
            initialize();
        }

        try {

            final byte[] salt;
            byte[] iv = null;
            final byte[] encryptedMessage;
            if (usingFixedSalt) {

                salt = fixedSaltInUse;

                synchronized (encryptCipher) {
                    encryptedMessage = encryptCipher.doFinal(message);
                }

            }
            else {

                // Create salt
                salt = saltGenerator.generateSalt(saltSizeBytes);

                // Create the IV
                iv = ivGenerator.generateIV(IVSizeBytes);

                IvParameterSpec ivParameterSpec = null;
                if (iv != null) {
                    ivParameterSpec = new IvParameterSpec(iv);
                }

                /*
                 * Perform encryption using the Cipher
                 */
                final PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, keyObtentionIterations,
                            ivParameterSpec);

                synchronized (encryptCipher) {
                    encryptCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
                    encryptedMessage = encryptCipher.doFinal(message);

                }

            }

            byte[] encryptedMessageWithIV = encryptedMessage;

            if (ivGenerator.includePlainIVInEncryptionResults()) {
                encryptedMessageWithIV = CommonUtils.appendArrays(iv, encryptedMessage);
            }

            // Finally we build an array containing both the unencrypted salt
            // and the result of the encryption. This is done only
            // if the salt generator we are using specifies to do so.
            if (saltGenerator.includePlainSaltInEncryptionResults()) {

                // Insert unhashed salt before the encryption result
                final byte[] encryptedMessageWithIVAndSalt = CommonUtils.appendArrays(salt, encryptedMessageWithIV);
                return encryptedMessageWithIVAndSalt;

            }

            return encryptedMessageWithIV;

        }
        catch (final InvalidKeyException e) {
            // The problem could be not having the unlimited strength policies
            // installed, so better give a usefull error message.
            handleInvalidKeyException(e);
            throw new EncryptionOperationNotPossibleException();
        }
        catch (final Exception e) {
            // If encryption fails, it is more secure not to return any
            // information about the cause in nested exceptions. Simply fail.
            throw new EncryptionOperationNotPossibleException();
        }

    }

    /**
     * <p>
     * Decrypts a message using the specified configuration.
     * </p>
     * <p>
     * The mechanisms applied to perform the decryption operation are described in
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" target="_blank">PKCS &#035;5: Password-Based
     * Cryptography Standard</a>.
     * </p>
     * <p>
     * If a random salt generator is used, this decryption operation will expect to find an unencrypted salt at the
     * beginning of the encrypted input, so that the decryption operation can be correctly performed (there is no other
     * way of knowing it).
     * </p>
     *
     * @param encryptedMessage the byte array message to be decrypted
     * @return the result of decryption
     * @throws EncryptionOperationNotPossibleException if the decryption operation fails, ommitting any further
     *             information about the cause for security reasons.
     * @throws EncryptionInitializationException if initialization could not be correctly done (for example, no password
     *             has been set).
     */
    @Override
    public byte[] decrypt(final byte[] encryptedMessage) throws EncryptionOperationNotPossibleException {

        if (encryptedMessage == null) {
            return null;
        }

        // Check initialization
        if (!isInitialized()) {
            initialize();
        }

        if (saltGenerator.includePlainSaltInEncryptionResults()) {
            // Check that the received message is bigger than the salt
            if (encryptedMessage.length <= saltSizeBytes) {
                throw new EncryptionOperationNotPossibleException();
            }
        }

        // if (this.ivGenerator.includePlainIVInEncryptionResults()) {
        // // Check that the received message is bigger than the IV
        // if (encryptedMessage.length <= this.IVSizeBytes) {
        // throw new EncryptionOperationNotPossibleException();
        // }
        // }

        try {

            // If we are using a salt generator which specifies the salt
            // to be included into the encrypted message itself, get it from
            // there. If not, the salt is supposed to be fixed and thus the
            // salt generator can be safely asked for it again.
            byte[] salt = null;
            byte[] encryptedMessageKernel = null;
            if (saltGenerator.includePlainSaltInEncryptionResults()) {

                final int saltStart = 0;
                final int saltSize = saltSizeBytes < encryptedMessage.length ? saltSizeBytes : encryptedMessage.length;
                final int encMesKernelStart = saltSizeBytes < encryptedMessage.length ? saltSizeBytes
                            : encryptedMessage.length;
                final int encMesKernelSize = saltSizeBytes < encryptedMessage.length
                            ? encryptedMessage.length - saltSizeBytes
                            : 0;

                salt = new byte[saltSize];
                encryptedMessageKernel = new byte[encMesKernelSize];

                System.arraycopy(encryptedMessage, saltStart, salt, 0, saltSize);
                System.arraycopy(encryptedMessage, encMesKernelStart, encryptedMessageKernel, 0, encMesKernelSize);

            }
            else if (!usingFixedSalt) {

                salt = saltGenerator.generateSalt(saltSizeBytes);
                encryptedMessageKernel = encryptedMessage;

            }
            else {
                // this.usingFixedSalt == true

                salt = fixedSaltInUse;
                encryptedMessageKernel = encryptedMessage;
            }

            // Logic for IV
            byte[] finalEncryptedMessage;
            byte[] iv;

            if (ivGenerator.includePlainIVInEncryptionResults()) {

                // Extracting the IV
                iv = Arrays.copyOfRange(encryptedMessageKernel, 0, IVSizeBytes / 8);
                finalEncryptedMessage = Arrays.copyOfRange(encryptedMessageKernel, iv.length,
                            encryptedMessageKernel.length);

            }
            else {
                // Fixed IV
                finalEncryptedMessage = encryptedMessageKernel;
                iv = ivGenerator.generateIV(IVSizeBytes);
            }

            final byte[] decryptedMessage;
            if (usingFixedSalt) {

                /*
                 * Fixed salt is being used, therefore no initialization supposedly needed
                 */

                synchronized (decryptCipher) {
                    decryptedMessage = decryptCipher.doFinal(encryptedMessageKernel);
                }

            }
            else {

                /*
                 * Perform decryption using the Cipher
                 */
                IvParameterSpec ivParameterSpec = null;
                if (iv != null) {
                    ivParameterSpec = new IvParameterSpec(iv);
                }

                final PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, keyObtentionIterations,
                            ivParameterSpec);

                synchronized (decryptCipher) {
                    decryptCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
                    decryptedMessage = decryptCipher.doFinal(finalEncryptedMessage);

                }

            }

            // Return the results
            return decryptedMessage;

        }
        catch (final InvalidKeyException e) {
            // The problem could be not having the unlimited strength policies
            // installed, so better give a usefull error message.
            handleInvalidKeyException(e);
            throw new EncryptionOperationNotPossibleException();
        }
        catch (final Exception e) {
            // If decryption fails, it is more secure not to return any
            // information about the cause in nested exceptions. Simply fail.
            throw new EncryptionOperationNotPossibleException();
        }

    }

    /*
     * Method used to provide an useful error message in the case that the user tried to use a strong PBE algorithm like
     * TripleDES and he/she has not installed the Unlimited Strength Policy files (the default message for this is
     * simply "invalid key size", which does not provide enough clues for the user to know what is really going on).
     */
    private void handleInvalidKeyException(final InvalidKeyException e) {

        if (e.getMessage() != null && e.getMessage().toUpperCase().indexOf("KEY SIZE") != -1) {

            throw new EncryptionOperationNotPossibleException("Encryption raised an exception. A possible cause is "
                        + "you are using strong encryption algorithms and "
                        + "you have not installed the Java Cryptography "
                        + "Extension (JCE) Unlimited Strength Jurisdiction "
                        + "Policy Files in this Java Virtual Machine");

        }

    }

}
