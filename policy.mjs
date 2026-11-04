export function restricted(key) {
  return key.kind === 'functionCall' || key.kind === 'gasFunctionCall';
}

function stableKey(key) {
  // A gas key's prepaid balance changes during normal use; it is observable state,
  // not an access permission. Nonce lane count is part of the key configuration.
  return JSON.stringify([key.publicKey, key.kind, key.receiverId || '', [...(key.methodNames || [])].sort(), key.allowance, key.numNonces || null]);
}

export function inspect(scan, baseline) {
  const issues = [];
  const baseKeys = new Map((baseline?.keys || []).map(k => [k.publicKey, k]));
  const nowKeys = new Map(scan.keys.map(k => [k.publicKey, k]));
  if (!baseline) issues.push({level:'info', title:'Baseline not approved', text:'Review this actual chain snapshot, then explicitly save it as the comparison baseline.'});
  else {
    for (const key of scan.keys) {
      const old = baseKeys.get(key.publicKey);
      if (!old) issues.push({level:(key.kind === 'fullAccess' || key.kind === 'gasFullAccess') ? 'block' : 'warn', title:(key.kind === 'fullAccess' || key.kind === 'gasFullAccess') ? 'New full-access key' : 'New access key', text:key.publicKey + (key.receiverId ? ' → ' + key.receiverId : '')});
      else if (stableKey(old) !== stableKey(key)) issues.push({level:'block', title:'Key permission changed', text:key.publicKey + ' no longer matches the approved scope.'});
    }
    for (const old of baseline.keys || []) if (!nowKeys.has(old.publicKey)) issues.push({level:'warn', title:'Baseline key is absent', text:old.publicKey});
    for (const [contract, hash] of Object.entries(baseline.codeSha256 || {})) {
      if (!scan.codeSha256[contract]) issues.push({level:'warn', title:'Pinned code could not be read', text:contract});
      else if (scan.codeSha256[contract] !== hash) issues.push({level:'block', title:'Contract code changed', text:contract + ' has a different SHA-256 code digest.'});
    }
  }
  for (const key of scan.keys) {
    if (key.kind === 'fullAccess' || key.kind === 'gasFullAccess') issues.push({level:'warn', title:'Full-access key present', text:key.publicKey + ' can make unrestricted account actions.'});
    if (key.kind === 'other') issues.push({level:'warn', title:'Unrecognized key permission', text:key.publicKey + ' uses a permission variant this KeyScope version does not interpret.'});
    if (restricted(key) && key.methodNames.length === 0) issues.push({level:'warn', title:'Function-Call key allows all receiver methods', text:key.publicKey + ' → ' + key.receiverId});
    if (restricted(key) && key.allowance === null) issues.push({level:'warn', title:'No gas allowance ceiling', text:key.publicKey + ' has no protocol allowance value.'});
  }
  for (const [contract, size] of Object.entries(scan.codeBytes || {})) if (size === 0) issues.push({level:'warn', title:'No contract code at receiver', text:contract + ' returned an empty code byte array at the observed block.'});
  return issues;
}
