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
    if (row.publishedAt !== null && row.publishedAt !== undefined
        && typeof row.publishedAt !== "string")
      throw new Error("session row " + number + " has an invalid publishedAt");

    return {
      target: row.target,
      host: row.host,
      session: row.session,
      publishedAt: row.publishedAt === undefined ? null : row.publishedAt
    };
  });
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

function terminalCommand(session) {
  if (!session || typeof session.target !== "string" || session.target.length === 0)
    throw new Error("cannot launch a session without a session target");

  // Quickshell receives an argv array, not shell text. Keeping the externally
  // supplied target in one element prevents quotes or metacharacters from being
  // interpreted by a shell.
  return ["omarchy-launch-terminal", "attached", "attach", session.target];
}

if (typeof module !== "undefined")
  module.exports = {
    parseCatalog: parseCatalog,
    fuzzyScore: fuzzyScore,
    filterSessions: filterSessions,
    terminalCommand: terminalCommand
  };
