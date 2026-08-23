import { createRoot } from "react-dom/client";
import "@wterm/react/css";
import { AttachedApp } from "./AttachedApp";
import "./styles.css";

const root = createRoot(document.getElementById("attached-root")!);
root.render(<AttachedApp />);

export const attachedUnmount = () => root.unmount();
