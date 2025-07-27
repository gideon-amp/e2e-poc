import { NativeModulesProxy } from "expo-modules-core";
import { QuantumCryptoModuleInterface } from "./QuantumCrypto.types";

// Get the native module object from the JSI or bridge
// @ts-ignore
// const QuantumCryptoModule: QuantumCryptoModuleInterface =
//   NativeModulesProxy.QuantumCrypto ??
//   (() => {
//     throw new Error(
//       "QuantumCrypto native module is not available. Make sure you have rebuilt the app after installing the module."
//     );
//   })();

// export default QuantumCryptoModule;

import { requireNativeModule } from "expo-modules-core";

const QuantumCryptoModule =
  requireNativeModule<QuantumCryptoModuleInterface>("QuantumCrypto");

export const NativeQuantumCrypto = QuantumCryptoModule;
export default QuantumCryptoModule;
