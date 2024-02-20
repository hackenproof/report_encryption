// encrypt files create report
async function encryptFileData(data, multiPublicKeys) {
  const publicKeysArray = await Promise.all(multiPublicKeys.map(async (key) => {
    const { keys } = await openpgp.key.readArmored(key);
    if (keys && keys.length > 0) {
      return keys[0];
    } else {
      throw new Error('Invalid PGP public key');
    }
  }));
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
//encrypt text fields create Report
async function encryptReport(multiPublicKeys, simples) {
  const publicKeysArray = await Promise.all(multiPublicKeys.map(async (key) => {
    const { keys } = await openpgp.key.readArmored(key);
    if (keys && keys.length > 0) {
      return keys[0];
    } else {
      throw new Error('Invalid PGP public key');
    }
  }));
  for (const e of simples) {
    const markdownValue = e.codemirror.getValue();
    if (markdownValue !== '') {
      if (!isEncrypted(markdownValue)) {
        try {
          const { data: encryptedData } = await openpgp.encrypt({
            message: openpgp.message.fromText(markdownValue),
            publicKeys: publicKeysArray,
          });
          e.value(encryptedData);
        } catch (error) {
          console.error('Error encrypting:', error);
        }
      }
    }
  }
}
// decrypt files
async function decryptData(data, filePrivetKeyInput, filePrivetPass) {
  try {
    const { keys: [privateKeyObj] } = await openpgp.key.readArmored(filePrivetKeyInput);
    if (filePrivetPass !== '') {
      await privateKeyObj.decrypt(filePrivetPass);
    }
    const { data: decryptedData } = await openpgp.decrypt({
      message: await openpgp.message.readArmored(data),
      privateKeys: [privateKeyObj],
    });
    return decryptedData;
  } catch (error) {
    console.log(error.message)
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
  try {
    const {keys: [publicKey]} = await openpgp.key.readArmored(publicKeyArmored);

    if (!publicKey) {
      throw new Error("Invalid public key");
    }

    const encryptedMessage = await openpgp.encrypt({
      message: openpgp.message.fromText(plainText),
      publicKeys: publicKey,
    });

    return encryptedMessage.data;
  } catch (error) {
    throw new Error("Encryption failed: " + error.message);

  }
}
// decrypt report
async function decryptMessage(encryptedMessage, privateKeyArmored, privateKeyPassphrase) {
  try {
      const privateKeyObj = await openpgp.key.readArmored(privateKeyArmored);
      if (privateKeyPassphrase !== '') {
          await privateKeyObj.keys[0].decrypt(privateKeyPassphrase);
      }
      const decryptedMessage = await openpgp.decrypt({
          message: await openpgp.message.readArmored(encryptedMessage),
          privateKeys: [privateKeyObj.keys[0]],
      });
      return decryptedMessage.data;
  } catch (error) {
      throw new Error('Decryption error:', error);
  }
}
// decrypt MD report 
async function decryptTextContents(textContents, privateKeyArmored, privateKeyPassphrase) {
  try {
      const privateKeyObj = await openpgp.key.readArmored(privateKeyArmored);
      if (privateKeyPassphrase !== '') {
          await privateKeyObj.keys[0].decrypt(privateKeyPassphrase);
      }
      const decryptedMessagesArray = await Promise.all(textContents.map(async (encryptedMessage) => {
          const decryptedMessage = await openpgp.decrypt({
              message: await openpgp.message.readArmored(encryptedMessage),
              privateKeys: [privateKeyObj.keys[0]],
          });
          return decryptedMessage.data;
      }));
      return decryptedMessagesArray;
  } catch (error) {
      throw new Error('Decryption error:', error);
  }
}