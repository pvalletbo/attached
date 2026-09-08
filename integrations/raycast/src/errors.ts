import {
  AttachedNotFoundError,
  CatalogCommandError,
  EncryptionPasswordProvider,
  InvalidAttachedPathError,
} from "./attached";
import { CatalogValidationError } from "./catalog";

export type DisplayError = {
  kind: "missing" | "preference" | "authentication" | "one-password" | "refresh" | "catalog";
  title: string;
  message: string;
};

export function displayError(error: unknown, provider: EncryptionPasswordProvider): DisplayError {
  if (error instanceof AttachedNotFoundError) {
    return {
      kind: "missing",
      title: "Attached Isn't Installed",
      message: "Install Attached, or set its absolute executable path in this extension's preferences.",
    };
  }
  if (error instanceof InvalidAttachedPathError) {
    return {
      kind: "preference",
      title: "Invalid Executable Path",
      message: "Set an absolute path to the Attached executable in this extension's preferences.",
    };
  }
  if (error instanceof CatalogValidationError) {
    return {
      kind: "catalog",
      title: "Incompatible Session Catalog",
      message: "Attached returned unexpected data. Update Attached and this extension, then try again.",
    };
  }
  if (error instanceof CatalogCommandError) {
    if (error.kind === "timeout") {
      return {
        kind: "refresh",
        title: "Session Refresh Timed Out",
        message:
          provider === "1password"
            ? "Unlock 1Password, then retry the refresh."
            : "Try entering the encryption password again.",
      };
    }
    if (error.kind === "too-large") {
      return {
        kind: "catalog",
        title: "Session Catalog Is Too Large",
        message: "Attached returned more session data than the extension can safely process.",
      };
    }
    if (error.kind === "launch") {
      return {
        kind: "missing",
        title: "Attached Could Not Start",
        message: "Check the Attached executable path and permissions in this extension's preferences.",
      };
    }
    if (error.kind === "exit" && error.exitReason === "authentication") {
      return provider === "1password"
        ? {
            kind: "authentication",
            title: "Attached State Could Not Be Unlocked",
            message: "This state could not be unlocked with 1Password. Verify it in Terminal and retry.",
          }
        : {
            kind: "authentication",
            title: "Incorrect Encryption Password",
            message: "That password could not unlock Attached. Enter it again.",
          };
    }
    if (error.kind === "exit" && error.exitReason === "one-password") {
      return {
        kind: "one-password",
        title: "1Password Is Locked or Unavailable",
        message: "Open or unlock 1Password, authorize its CLI if prompted, then retry.",
      };
    }
    if (error.kind === "exit" && error.exitReason === "unsupported") {
      return {
        kind: "catalog",
        title: "Attached Must Be Updated",
        message: "Install an Attached build that supports the machine-readable attached sessions command, then retry.",
      };
    }
    if (error.kind === "aborted") {
      return {
        kind: "refresh",
        title: "Refresh Cancelled",
        message: "Retry to refresh synchronized sessions.",
      };
    }

    const exit = error.exitCode === null ? "" : ` (exit ${error.exitCode})`;
    return {
      kind: "refresh",
      title: "Could Not Refresh Sessions",
      message:
        provider === "1password"
          ? `Attached failed${exit}. Run attached --use-1password sessions in Terminal for details.`
          : `Attached failed${exit}. Enter the password again, or run attached sessions in Terminal for details.`,
    };
  }

  return {
    kind: "refresh",
    title: "Could Not Refresh Sessions",
    message: "An unexpected error occurred. Retry, or run Attached in Terminal for details.",
  };
}
