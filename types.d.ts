export type SerializablePrimitive = string | number | boolean | null;
export type SerializableArray = Serializable[];
export type SerializableObject = { [key: string]: Serializable };
export type Serializable = SerializablePrimitive | SerializableArray | SerializableObject;

export type EncryptedData = { data: string; v: string };

export type CryptoParams = { message: Serializable; pass: string };

export interface ServerCrypt {
  encryptMsg: (params: CryptoParams) => EncryptedData;
  decryptMsg: (params: CryptoParams) => Serializable;
}

export interface FrontCrypt {
  // Методы клиентской части
}

// Объявляем экспорт модуля
declare const serverCrypt: ServerCrypt;
declare const frontCrypt: FrontCrypt;

export default {
  serverCrypt,
  frontCrypt,
};

// Чтобы использовать именованные методы
export { serverCrypt, frontCrypt };
