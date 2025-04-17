export type SerializablePrimitive = string | number | boolean | null;
export type SerializableArray = Serializable[];
export type SerializableObject = { [key: string]: Serializable };
export type Serializable = SerializablePrimitive | SerializableArray | SerializableObject;

export type EncryptedData = { data: string; v: string };

export type CryptoParams =  { message: Serializable; pass: string };

export default interface Crypt {
  serverCrypt: {
    encryptMsg: (params: CryptoParams) => EncryptedData,
    decryptMsg: (params: CryptoParams) => Serializable
  },
  frontCrypt: {}
}
