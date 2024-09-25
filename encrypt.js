function checkIsValid(keyObj) {
  if (!keyObj.isPublic() && !keyObj.isPrivate()) {
    throw new Error("Key is not valid");
  }

  const now = new Date();
  const validUntil = keyObj.getExpirationTime();

  if (validUntil && validUntil < now) {
    throw new Error('Key is expired');
  }
}

function isPublic(keyObj){
  checkIsValid(keyObj);

  if (!keyObj.isPublic()){
    throw new Error("Key is not public");
  }
}

function isPrivate(keyObj){
  checkIsValid(keyObj);

  if (!keyObj.isPrivate()){
    throw new Error("Key is not private");
  }
}

async function encryptFileData(data, multiPublicKeys) {
  const publicKeysArray = [];

  // Collect valid public keys and log errors for invalid ones
  for (const key of multiPublicKeys) {
    try {
      const { keys } = await openpgp.key.readArmored(key);
      if (keys && keys.length > 0) {
        publicKeysArray.push(keys[0]);  // Add valid keys
      } else {
        console.error("Invalid PGP public key detected:", key);
      }
    } catch (error) {
      console.error("Error reading PGP public key:", error.message, key);
    }
  }

  // Check if we have any valid public keys to proceed with encryption
  if (publicKeysArray.length === 0) {
    console.error("No valid public keys available for encryption.");
    throw new Error("No valid public keys available for encryption.");
  }

  try {
    const { data: encryptedData } = await openpgp.encrypt({
      message: openpgp.message.fromText(data),
      publicKeys: publicKeysArray
    });
    return encryptedData;
  } catch (error) {
    console.error('Encryption error:', error);
    throw error;
  }
}

/**
 * Ecnrypting file
 * @param {object} fileData Uint8Array file data
 * @param {string} publicKeyArmored public pgp key
 * @return {string} encrypted file representation 
 */

async function encryptFile(fileData, publicKeyArmored) {
  if(!fileData) {
    throw new Error('Encryption error: No file provided');
  }

  if(!publicKeyArmored?.length) {
    throw new Error('Encryption error: No public key provided');
  }
  try {
  // Public key import
  const { keys: [publicKey] } = await openpgp.key.readArmored(publicKeyArmored);

  // Encrypting
  const { data: encrypted } = await openpgp.encrypt({
      message: await openpgp.message.fromBinary(fileData),
      publicKeys: [publicKey]
  });

  return encrypted;
  } catch(error) {
    throw new Error(error.message);
  }
}


// encrypt text fields create report
async function encryptReport(multiPublicKeys, simples) {
  const publicKeysArray = [];

  // Collect valid public keys and log errors for invalid ones
  for (const key of multiPublicKeys) {
    try {
      const { keys } = await openpgp.key.readArmored(key);
      if (keys && keys.length > 0) {
        publicKeysArray.push(keys[0]);  // Add valid keys
      } else {
        console.error("Invalid PGP public key detected:", key);
      }
    } catch (error) {
      console.error("Error reading PGP public key:", error.message, key);
    }
  }

  // Check if we have valid public keys to proceed with encryption
  if (publicKeysArray.length === 0) {
    console.error("No valid public keys available for encryption.");
    throw new Error("No valid public keys available for encryption.");
  }

  // Encrypt markdown content
  for (const e of simples) {
    const markdownValue = e.codemirror.getValue();
    if (markdownValue !== '' && !isEncrypted(markdownValue)) {
      try {
        const { data: encryptedData } = await openpgp.encrypt({
          message: openpgp.message.fromText(markdownValue),
          publicKeys: publicKeysArray,
        });
        e.value(encryptedData);  // Set the encrypted value
      } catch (error) {
        console.error('Error encrypting:', error);
      }
    }
  }
}

// decrypt files
async function decryptData(data, filePrivateKeyInput, filePrivatePass) {
  try {
    const { keys: [privateKeyObj] } = await openpgp.key.readArmored(filePrivateKeyInput);
    
    if (filePrivatePass !== '') {
      await privateKeyObj.decrypt(filePrivatePass);
    }
    
    const { data: decryptedData } = await openpgp.decrypt({
      message: await openpgp.message.readArmored(data),
      privateKeys: [privateKeyObj],
    });
    return decryptedData;
  } catch (error) {
    console.error("Decryption error:", error.message);
    throw error;
  }
}

// encrypt report sharing
async function encryptData(data, publicKey) {
  try {
    const { keys: [publicKeyObj] } = await openpgp.key.readArmored(publicKey);
    const { data: encryptedData } = await openpgp.encrypt({
      message: openpgp.message.fromText(data),
      publicKeys: publicKeyObj
    });
    return encryptedData;
  } catch (error) {
    console.error('Encryption error:', error);
    throw error;
  }
}

// Encrypt share report
async function encryptMessage(plainText, publicKeyArmored) {
  if(!plainText?.length) {
    throw new Error('No text provided');
  }

  if(!publicKeyArmored?.length) {
    throw new Error('No public key provided');
  }

  try {
    const { keys: [publicKey] } = await openpgp.key.readArmored(publicKeyArmored);

    if(!publicKey) {
      throw new Error("Invalid public key");
    } else {
      isPublic(publicKey);
    }

    const { data: encryptedMessage } = await openpgp.encrypt({
      message: openpgp.message.fromText(plainText),
      publicKeys: publicKey,
    });

    return encryptedMessage;
  } catch (error) {
    throw new Error(error.message);
  }
}

// decrypt report
async function decryptMessage(encryptedMessage, privateKeyArmored, privateKeyPassphrase) {
  if(!encryptedMessage?.length) {
    throw new Error('No encrypted message provided');
  }

  if(!privateKeyArmored?.length) {
    throw new Error('No private key provided');
  }

  try {
    const { keys: [privateKeyObj] } = await openpgp.key.readArmored(privateKeyArmored);

    if(!privateKeyObj) {
      throw new Error("Invalid private key");
    } else {
      isPrivate(privateKeyObj);
    }

    if (!privateKeyObj.isDecrypted()) {
      try {
        await privateKeyObj.decrypt(privateKeyPassphrase);
      } catch (error) {
        throw new Error('Private key password is invalid');
      }
    }

    const { data: decryptedMessage } = await openpgp.decrypt({
      message: await openpgp.message.readArmored(encryptedMessage),
      privateKeys: [privateKeyObj],
    });

    return decryptedMessage;
  } catch (error) {
    throw new Error(error.message);
  }
}
// decrypt MD report 
async function decryptTextContents(textContents, privateKeyArmored, privateKeyPassphrase) {
  if(!textContents?.length) {
    throw new Error('No encrypted messages provided');
  }

  if(!privateKeyArmored?.length) {
    throw new Error('No private key provided');
  }

  try {
    const { keys: [privateKeyObj] } = await openpgp.key.readArmored(privateKeyArmored);

    if(!privateKeyObj) {
      throw new Error("Invalid private key");
    } else {
      isPrivate(privateKeyObj);
    }

    if (!privateKeyObj.isDecrypted()) {
      try {
        await privateKeyObj.decrypt(privateKeyPassphrase);
      } catch (error) {
        throw new Error('Private key password is invalid');
      }
    }

    const decryptedMessagesArray = await Promise.all(textContents.map(async (encryptedMessage) => {
      const { data: decryptedMessage } = await openpgp.decrypt({
        message: await openpgp.message.readArmored(encryptedMessage),
        privateKeys: [privateKeyObj],
      });
      return decryptedMessage;
    }));

    return decryptedMessagesArray;
  } catch (error) {
    throw new Error(error.message);
  }
}