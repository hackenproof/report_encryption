async function readKeysArmored(keysArmored) {
  try {
    const { keys } = await openpgp.key.readArmored(keysArmored);
    if (keys && keys.length > 0) {
      return keys[0];
    } else {
      throw new Error('Invalid PGP key');
    }
  } catch (error) {
    throw new Error('Error reading armored keys: ' + error.message);
  }
}

async function encryptText(text, publicKeys) {
  try {
    const publicKeysArray = await Promise.all(publicKeys.map(async (key) => await readKeysArmored(key)));
    const { data: encryptedData } = await openpgp.encrypt({
      message: await openpgp.message.fromText(text),
      publicKeys: publicKeysArray
    });
    return encryptedData;
  } catch (error) {
    throw new Error('Encryption error: ' + error.message);
  }
}

async function decryptText(encryptedData, privateKeyArmored, privateKeyPassphrase) {
  try {
    const privateKeyObj = await openpgp.key.readArmored(privateKeyArmored);
    if (privateKeyPassphrase !== '') {
      await privateKeyObj.keys[0].decrypt(privateKeyPassphrase);
    }
    const { data: decryptedData } = await openpgp.decrypt({
      message: await openpgp.message.readArmored(encryptedData),
      privateKeys: [privateKeyObj.keys[0]],
    });
    return decryptedData;
  } catch (error) {
    throw new Error('Decryption error: ' + error.message);
  }
}

async function encryptMessage(plainText, publicKeyArmored) {
  try {
    const publicKey = await readKeysArmored(publicKeyArmored);
    const encryptedMessage = await openpgp.encrypt({
      message: await openpgp.message.fromText(plainText),
      publicKeys: publicKey,
    });
    return encryptedMessage.data;
  } catch (error) {
    throw new Error("Encryption failed: " + error.message);
  }
}

// async function decryptMessage(encryptedMessage, privateKeyArmored, privateKeyPassphrase) {
//   try {
//     const privateKeyObj = await openpgp.key.readArmored(privateKeyArmored);
//     if (privateKeyPassphrase !== '') {
//       await privateKeyObj.keys[0].decrypt(privateKeyPassphrase);
//     }
//     const decryptedMessage = await openpgp.decrypt({
//       message: await openpgp.message.readArmored(encryptedMessage),
//       privateKeys: [privateKeyObj.keys[0]],
//     });
//     return decryptedMessage.data;
//   } catch (error) {
//     throw new Error('Decryption error: ' + error.message);
//   }
// }

// async function decryptTextContents(textContents, privateKeyArmored, privateKeyPassphrase) {
//   try {
//     const privateKeyObj = await openpgp.key.readArmored(privateKeyArmored);
//     if (privateKeyPassphrase !== '') {
//       await privateKeyObj.keys[0].decrypt(privateKeyPassphrase);
//     }
//     const decryptedMessagesArray = await Promise.all(textContents.map(async (encryptedMessage) => {
//       const decryptedMessage = await openpgp.decrypt({
//         message: await openpgp.message.readArmored(encryptedMessage),
//         privateKeys: [privateKeyObj.keys[0]],
//       });
//       return decryptedMessage.data;
//     }));
//     return decryptedMessagesArray;
//   } catch (error) {
//     throw new Error('Decryption error: ' + error.message);
//   }
// }
async function decryptDataContents(dataContents, privateKeyArmored, privateKeyPassphrase) {
  try {
    const privateKeyObj = await openpgp.key.readArmored(privateKeyArmored);
    if (privateKeyPassphrase !== '') {
      await privateKeyObj.keys[0].decrypt(privateKeyPassphrase);
    }
    const decryptedContentsArray = await Promise.all(dataContents.map(async (encryptedContent) => {
      const decryptedContent = await openpgp.decrypt({
        message: await openpgp.message.readArmored(encryptedContent),
        privateKeys: [privateKeyObj.keys[0]],
      });
      return decryptedContent.data;
    }));
    return decryptedContentsArray;
  } catch (error) {
    throw new Error('Decryption error:', error);
  }
}