export type SerializablePrimitive = string | number | boolean | null;
export type SerializableArray = Serializable[];
export type SerializableObject = { [key: string]: Serializable };
export type Serializable = SerializablePrimitive | SerializableArray | SerializableObject;

export type encryptedData = { data: string; v: string };

export declare const encryptMsg: (params: { message: Serializable; pass: string }) => encryptedData;
export declare const decryptMsg: (params: { message: encryptedData; pass: string }) => Serializable;
