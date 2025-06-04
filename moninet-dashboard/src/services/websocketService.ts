// TODO: Get WebSocket URL from environment variable
// Placeholder
import {
  NetworkDataMessage,
  ConnectivityStatus as ConnectivityStatusInterface,
} from "../interfaces/networkData";

const WEBSOCKET_URL = "ws://localhost:8000/ws/network-data";

let socket: WebSocket | null = null;
let messageListeners: Array<(data: any) => void> = [];

const connect = () => {
  if (socket && socket.readyState === WebSocket.OPEN) {
    console.log("WebSocket is already connected.");
    return;
  }

  socket = new WebSocket(WEBSOCKET_URL);

  socket.onopen = () => {
    console.log("WebSocket connection established");
    const statusPayload: ConnectivityStatusInterface = {
      serviceStatus: "connected",
      lastMessageTimestamp: Date.now(),
    };
    messageListeners.forEach((listener) =>
      listener({ type: "CONNECTIVITY_UPDATE", payload: statusPayload }),
    );
  };

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      messageListeners.forEach((listener) => listener(data));
    } catch (error) {
      console.error("Failed to parse WebSocket message:", error);
    }
  };

  socket.onerror = (error) => {
    console.error("WebSocket error:", error);
    const statusPayload: ConnectivityStatusInterface = {
      serviceStatus: "error",
      lastMessageTimestamp: Date.now(),
    };
    messageListeners.forEach((listener) =>
      listener({ type: "CONNECTIVITY_UPDATE", payload: statusPayload }),
    );
  };

  socket.onclose = (event) => {
    console.log("WebSocket connection closed:", event.reason, event.code);
    const statusPayload: ConnectivityStatusInterface = {
      serviceStatus: "disconnected",
      lastMessageTimestamp: Date.now(),
    };
    messageListeners.forEach((listener) =>
      listener({ type: "CONNECTIVITY_UPDATE", payload: statusPayload }),
    );
    socket = null;
  };
};

const disconnect = () => {
  if (socket) {
    socket.close();
  }
};

const sendMessage = (message: any) => {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(message));
  } else {
    console.error("WebSocket is not connected. Cannot send message.");
  }
};

const addMessageListener = (listener: (data: any) => void) => {
  messageListeners.push(listener);
};

const removeMessageListener = (listener: (data: any) => void) => {
  messageListeners = messageListeners.filter((l) => l !== listener);
};

export const websocketService = {
  connect,
  disconnect,
  sendMessage,
  addMessageListener,
  removeMessageListener,
};