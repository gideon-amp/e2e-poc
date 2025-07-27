import { StatusBar } from "expo-status-bar";
import { SafeAreaView, StyleSheet } from "react-native";
import { QuantumMessagingDemo } from "./src/components/QuantumMessagingDemo";

import { Buffer } from "buffer";

// Set up global polyfills
global.Buffer = Buffer;

export default function App() {
  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="auto" />
      <QuantumMessagingDemo />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
    alignItems: "center",
    justifyContent: "center",
  },
});
