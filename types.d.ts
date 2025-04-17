export type SerializablePrimitive = string | number | boolean | null;
export type SerializableArray = Serializable[];
export type SerializableObject = { [key: string]: Serializable };
export type Serializable = SerializablePrimitive | SerializableArray | SerializableObject;

export type CryptedData = { data: string; v: string };

export type EncryptParams = { message: Serializable; pass: string };
export type DecryptParams = { message: CryptedData; pass: string };

export interface ServerCrypt {
  encryptMsg: (params: EncryptParams) => CryptedData;
  decryptMsg: (params: DecryptParams) => string;
  unpack: (base64Key: string) => Buffer;
  pack: (bufferKey: Buffer) => string;
}

export interface FrontCrypt {
  // Методы клиентской части
}

/* Разбираться! Не работает в старых версиях
// Объявляем экспорт модуля
declare const serverCrypt: ServerCrypt;
declare const frontCrypt: FrontCrypt;

export default {
  serverCrypt,
  frontCrypt,
};

// Чтобы использовать именованные методы
export { serverCrypt, frontCrypt };
*/

declare namespace Crypt {
  export const serverCrypt: ServerCrypt;
  export const frontCrypt: FrontCrypt;
}

export default Crypt;
