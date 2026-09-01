// The shell imports this file as a QML JavaScript library. The CommonJS export at
// the bottom also lets `node --test` exercise the data boundary without Omarchy.

function parseCatalog(raw) {
  var parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error("Attached did not return valid JSON");
  }

  if (!Array.isArray(parsed))
    throw new Error("Attached session catalog must be a JSON array");
  if (parsed.length > 4096)
    throw new Error("Attached returned too many sessions");

  return parsed.map(function(row, index) {
    var number = index + 1;
    if (!row || typeof row !== "object" || Array.isArray(row))
      throw new Error("session row " + number + " must be an object");
    for (var field of ["target", "host", "session"]) {
      if (typeof row[field] !== "string" || row[field].length === 0)
        throw new Error("session row " + number + " has an invalid " + field);
    }
    if (row.target !== row.host + "/" + row.session)
      throw new Error("session row " + number + " has an invalid target");
    var attachedVersion = parseVersion(row.attachedVersion, "attachedVersion", number, true);
    var herdrVersion = parseVersion(row.herdrVersion, "herdrVersion", number, false);
    if (row.publishedAt !== null && row.publishedAt !== undefined
        && (typeof row.publishedAt !== "string" || isNaN(Date.parse(row.publishedAt))))
      throw new Error("session row " + number + " has an invalid publishedAt");

    return {
      target: row.target,
      host: row.host,
      session: row.session,
      attachedVersion: attachedVersion,
      herdrVersion: herdrVersion,
      publishedAt: row.publishedAt === undefined ? null : row.publishedAt
    };
  });
}

function parseVersion(value, field, rowNumber, optional) {
  if (optional && value === null)
    return null;
  if (!Array.isArray(value) || value.length !== 3)
    throw new Error("session row " + rowNumber + " has an invalid " + field);
  for (var component of value) {
    if (typeof component !== "number" || !isFinite(component)
        || Math.floor(component) !== component || component < 0 || component > 65535)
      throw new Error("session row " + rowNumber + " has an invalid " + field);
  }
  return value.slice();
}

function versionSummary(version) {
  return version === null ? "unknown" : version.join(".");
}

function lastPublishSummary(publishedAt, nowMilliseconds) {
  if (publishedAt === null)
    return "unknown";
  var now = nowMilliseconds === undefined ? Date.now() : nowMilliseconds;
  var published = Date.parse(publishedAt);
  if (published - now > 30000)
    return "clock skew";

  var ageSeconds = Math.max(0, Math.floor((now - published) / 1000));
  if (ageSeconds < 60)
    return ageSeconds + "s ago";
  if (ageSeconds < 3600)
    return Math.floor(ageSeconds / 60) + "m ago";
  if (ageSeconds < 86400)
    return Math.floor(ageSeconds / 3600) + "h ago";
  return Math.floor(ageSeconds / 86400) + "d ago";
}

function metadataSummary(session, nowMilliseconds) {
  return "Attached " + versionSummary(session.attachedVersion)
    + "  •  Herdr " + versionSummary(session.herdrVersion)
    + "  •  Last publish " + lastPublishSummary(session.publishedAt, nowMilliseconds);
}

function fuzzyScore(query, candidate) {
  var needle = query.toLocaleLowerCase();
  var haystack = candidate.toLocaleLowerCase();
  if (needle.length === 0)
    return 0;

  var score = 0;
  var previous = -1;
  for (var index = 0; index < needle.length; index++) {
    var position = haystack.indexOf(needle[index], previous + 1);
    if (position === -1)
      return null;

    // Compact runs rank above scattered matches. Word and path boundaries receive
    // a small bonus so `ow` naturally finds `office/work`.
    score += position;
    if (previous >= 0)
      score += position - previous - 1;
    if (position === 0 || "/ _-".indexOf(haystack[position - 1]) !== -1)
      score -= 4;
    if (position === previous + 1)
      score -= 2;
    previous = position;
  }
  return score;
}

function filterSessions(sessions, query) {
  if (!query)
    return sessions.slice();

  return sessions.map(function(session, index) {
    return {
      session: session,
      index: index,
      score: fuzzyScore(query, session.target)
    };
  }).filter(function(candidate) {
    return candidate.score !== null;
  }).sort(function(left, right) {
    return left.score - right.score || left.index - right.index;
  }).map(function(candidate) {
    return candidate.session;
  });
}

function encryptionPasswordProvider(raw) {
  var text = String(raw || "").trim();
  if (text.length === 0)
    return "password";
  if (text.length > 4096)
    throw new Error("Attached Omarchy configuration is too large");

  var parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error("Attached Omarchy configuration is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error("Attached Omarchy configuration must be a JSON object");

  var provider = parsed.encryptionPasswordProvider;
  if (provider !== "password" && provider !== "1password")
    throw new Error("encryptionPasswordProvider must be \"password\" or \"1password\"");
  return provider;
}

function catalogCommand(provider) {
  if (provider === "1password")
    return ["attached", "--use-1password", "sessions"];
  if (provider === "password")
    return ["attached", "sessions", "--password-stdin"];
  throw new Error("unsupported encryption password provider");
}

function catalogErrorMessage(raw, exitCode, provider) {
  var detail = String(raw || "").toLocaleLowerCase();
  if (provider === "1password") {
    if (detail.indexOf("1password") !== -1) {
      return "Open or unlock 1Password (Ctrl+O), then press Ctrl+R. If it still fails, run `attached --use-1password sessions` in a terminal for details.";
    }
    if (detail.indexOf("encrypted local secret authentication failed") !== -1) {
      return "This Attached state could not be unlocked with 1Password. Run `attached --use-1password sessions` in a terminal for setup details.";
    }
    return "Attached could not refresh sessions (exit " + exitCode
      + "). Run `attached --use-1password sessions` in a terminal for details, then press Ctrl+R.";
  }

  if (detail.indexOf("encrypted local secret authentication failed") !== -1) {
    return "That encryption password could not unlock Attached. Press Ctrl+R to try again.";
  }
  return "Attached could not refresh sessions (exit " + exitCode
    + "). Press Ctrl+R to re-enter the encryption password, or run `attached sessions` in a terminal for details.";
}

function terminalCommand(session, provider) {
  if (!session || typeof session.target !== "string" || session.target.length === 0)
    throw new Error("cannot launch a session without a session target");

  // Quickshell receives an argv array, not shell text. Keeping the externally
  // supplied target in one element prevents quotes or metacharacters from being
  // interpreted by a shell. Password users enter it in the launched terminal;
  // 1Password remains noninteractive when explicitly configured.
  var command = ["omarchy-launch-terminal", "attached"];
  if (provider === "1password")
    command.push("--use-1password");
  else if (provider !== "password")
    throw new Error("unsupported encryption password provider");
  command.push("attach", session.target);
  return command;
}

if (typeof module !== "undefined")
  module.exports = {
    parseCatalog: parseCatalog,
    versionSummary: versionSummary,
    lastPublishSummary: lastPublishSummary,
    metadataSummary: metadataSummary,
    fuzzyScore: fuzzyScore,
    filterSessions: filterSessions,
    encryptionPasswordProvider: encryptionPasswordProvider,
    catalogCommand: catalogCommand,
    catalogErrorMessage: catalogErrorMessage,
    terminalCommand: terminalCommand
  };
