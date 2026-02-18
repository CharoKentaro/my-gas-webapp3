/**
 * TRC Unified Foundation Core
 * Version: 25.8 (Zenith / Standalone / User-Local-DB)
 * 
 * 概要:
 * - 訪問者モードでの実行に対応するため、スプレッドシートDBを廃止。
 * - 代わりに「UserProperties (ユーザー自身の保存領域)」を利用し、
 *   個人情報を管理者（ちゃろさん）に渡さずに履歴管理・比較機能を実現。
 * - 基盤機能（暗号化、API接続、Gmail連携）は維持。
 */

// =====================================================================
// [Foundation] 0. 設定 & 定数
// =====================================================================

// ★設定用シートID（管理者がモデルリスト更新時のみ使用）
const DEFAULT_CONFIG_SHEET_ID = "YOUR_CONFIG_SPREADSHEET_ID_HERE"; 

const CACHE_DURATION_MS = 6 * 60 * 60 * 1000;
const MAX_RETRIES = 2; 
const RETRY_BASE_DELAY_MS = 1500; 
const DATA_SIZE_LIMIT_BYTES = 100000; // データ保存上限 (約100KB)
const CHUNK_SIZE = 8500; 
const LOG_RETENTION_DAYS = 90;
const FALLBACK_MODELS = ["gemini-3-pro-preview", "gemini-2.5-flash", "gemini-2.5-pro"];
const ALLOWED_MODEL_PREFIXES = ["gemini-", "models/gemini-", "learnlm-", "corallm-"];

// =====================================================================
// [Foundation] 1. ユーティリティ & 型定義
// =====================================================================

const Utils_ = {
  formatDate: function(date, format = 'YYYY/MM/DD HH:mm') {
    const d = date instanceof Date ? date : new Date(date);
    const pad = n => String(n).padStart(2, '0');
    return format.replace('YYYY', d.getFullYear()).replace('MM', pad(d.getMonth()+1)).replace('DD', pad(d.getDate())).replace('HH', pad(d.getHours())).replace('mm', pad(d.getMinutes()));
  },
  generateId: function(prefix = '') { return prefix + Utilities.getUuid().replace(/-/g, '').substring(0, 12); },
  deepMerge: function(target, source) {
    const output = Object.assign({}, target);
    if (typeof target === 'object' && typeof source === 'object') {
      Object.keys(source).forEach(key => {
        if (typeof source[key] === 'object' && !Array.isArray(source[key])) output[key] = this.deepMerge(target[key] || {}, source[key]);
        else output[key] = source[key];
      });
    }
    return output;
  }
};

const DataSchema_ = {
  validate: function(data, schema) {
    if (!schema) return { valid: true };
    const errors = [];
    for (const [field, rules] of Object.entries(schema)) {
      const value = data[field];
      if (rules.required && (value === undefined || value === null)) { errors.push(`Field '${field}' is required`); continue; }
      if (value !== undefined && value !== null) {
        if (rules.type === 'date' && !(value instanceof Date) && isNaN(new Date(value))) errors.push(`Field '${field}' must be a valid date`);
        else if (rules.type === 'array' && !Array.isArray(value)) errors.push(`Field '${field}' must be an array`);
        else if (rules.type !== 'array' && rules.type !== 'date' && typeof value !== rules.type) errors.push(`Field '${field}' must be ${rules.type}`);
      }
    }
    return { valid: errors.length === 0, errors };
  }
};

const CircuitBreaker_ = {
  getCache: function() { return CacheService.getScriptCache(); },
  isOpen: function(model) { return this.getCache().get(`CB_${model}`) === 'OPEN'; },
  recordFailure: function(model) { this.getCache().put(`CB_${model}`, 'OPEN', 60); console.warn(`Circuit Breaker OPEN: ${model}`); },
  recordSuccess: function(model) { this.getCache().remove(`CB_${model}`); }
};

// =====================================================================
// [Foundation] 2. セキュリティ (PBKDF2 + HMAC)
// =====================================================================
const Security_ = {
  getUserSecret: function(rotate = false) {
    try {
      const props = PropertiesService.getUserProperties();
      let secret = props.getProperty('USER_SECRET');
      if (!secret) {
        secret = 'v1:' + Utilities.getUuid();
        props.setProperties({ 'USER_SECRET': secret, 'SECRET_VERSION': '1', 'SECRET_CREATED_AT': new Date().toISOString() });
        return secret;
      }
      if (rotate) {
        const oldVersion = parseInt(props.getProperty('SECRET_VERSION') || '1');
        const newSecret = `v${oldVersion + 1}:` + Utilities.getUuid();
        const oldSecrets = JSON.parse(props.getProperty('OLD_SECRETS') || '[]');
        oldSecrets.unshift({ version: oldVersion, secret: secret, retiredAt: new Date().toISOString() });
        if (oldSecrets.length > 5) oldSecrets.pop();
        props.setProperties({ 'USER_SECRET': newSecret, 'SECRET_VERSION': (oldVersion+1).toString(), 'SECRET_CREATED_AT': new Date().toISOString(), 'OLD_SECRETS': JSON.stringify(oldSecrets) });
        return newSecret;
      }
      return secret;
    } catch (e) { throw new Error("SECURITY_INIT_FAILED"); }
  },
  encrypt: function(text) {
    if (!text) return "";
    try {
      const rawSecret = this.getUserSecret();
      const salt = Utilities.getUuid(); const iv = Utilities.getUuid();
      let derivedKey = rawSecret;
      for(let i=0; i<3000; i++) { derivedKey = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, derivedKey + salt + i)); }
      const keyStream = Utilities.computeHmacSha256Signature(iv, derivedKey);
      const textBytes = Utilities.newBlob(text).getBytes();
      const encryptedBytes = textBytes.map((byte, i) => byte ^ keyStream[i % keyStream.length]);
      const cipherB64 = Utilities.base64Encode(encryptedBytes);
      const dataToSign = salt + ":" + iv + ":" + cipherB64;
      const mac = Utilities.base64Encode(Utilities.computeHmacSha256Signature(dataToSign, derivedKey));
      return dataToSign + ":" + mac;
    } catch (e) { throw new Error("ENCRYPTION_FAILED"); }
  },
  decrypt: function(encryptedStr) {
    if (!encryptedStr) return "";
    if (encryptedStr.split(":").length === 2) return this._decryptLegacy(encryptedStr);
    const currentSecret = this.getUserSecret();
    let res = this._decryptStrong(encryptedStr, currentSecret);
    if (res !== null) return res;
    try {
      const oldSecrets = JSON.parse(PropertiesService.getUserProperties().getProperty('OLD_SECRETS') || '[]');
      for (const entry of oldSecrets) { res = this._decryptStrong(encryptedStr, entry.secret); if (res !== null) return res; }
    } catch(e) {}
    return "";
  },
  _decryptStrong: function(encryptedStr, rawSecret) {
    try {
      const parts = encryptedStr.split(":");
      if (parts.length !== 4) return null;
      const [salt, iv, cipherB64, receivedMac] = parts;
      let derivedKey = rawSecret;
      for(let i=0; i<3000; i++) { derivedKey = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, derivedKey + salt + i)); }
      const dataToSign = salt + ":" + iv + ":" + cipherB64;
      const computedMac = Utilities.base64Encode(Utilities.computeHmacSha256Signature(dataToSign, derivedKey));
      if (computedMac !== receivedMac) return null;
      const keyStream = Utilities.computeHmacSha256Signature(iv, derivedKey);
      const encryptedBytes = Utilities.base64Decode(cipherB64);
      const decryptedBytes = encryptedBytes.map((byte, i) => byte ^ keyStream[i % keyStream.length]);
      const result = Utilities.newBlob(decryptedBytes).getDataAsString();
      if (result && !/[\uFFFD]/.test(result)) return result;
      return null;
    } catch(e) { return null; }
  },
  _decryptLegacy: function(str) {
    try {
      const secret = this.getUserSecret();
      const parts = str.split(":");
      const salt = parts[0];
      const bytes = Utilities.base64Decode(parts[1]);
      const ks = Utilities.computeHmacSha256Signature(salt, secret);
      const dec = bytes.map((b,i) => b ^ ks[i % ks.length]);
      return Utilities.newBlob(dec).getDataAsString();
    } catch(e) { return ""; }
  }
};

// =====================================================================
// [Foundation] 3. データ保存 (Chunking / Local DB Support)
// =====================================================================
function Foundation_saveChunkedData_(keyPrefix, dataStr) {
  const props = PropertiesService.getUserProperties();
  const metaKey = keyPrefix + '_META';
  const oldMeta = props.getProperty(metaKey);
  if (oldMeta) { try { const c = JSON.parse(oldMeta).chunks; for(let i=0; i<c; i++) props.deleteProperty(keyPrefix+'_'+i); } catch(e){} }
  const chunks = [];
  for(let i=0; i<dataStr.length; i+=CHUNK_SIZE) chunks.push(dataStr.substring(i, i+CHUNK_SIZE));
  const payload = {};
  payload[metaKey] = JSON.stringify({ chunks: chunks.length, timestamp: new Date().getTime() });
  chunks.forEach((chunk, index) => { payload[keyPrefix + '_' + index] = chunk; });
  props.setProperties(payload);
}

function Foundation_loadChunkedData_(keyPrefix) {
  const props = PropertiesService.getUserProperties();
  const legacyData = props.getProperty(keyPrefix);
  if (legacyData && !props.getProperty(keyPrefix+'_META')) return legacyData;
  const metaJson = props.getProperty(keyPrefix+'_META');
  if (!metaJson) return null;
  try {
    const meta = JSON.parse(metaJson);
    let fullData = "";
    for(let i=0; i<meta.chunks; i++) { const c = props.getProperty(keyPrefix+'_'+i); if(!c) return null; fullData += c; }
    return fullData;
  } catch(e) { return null; }
}

function Foundation_saveUserData(dataObj, schema = null) {
  try {
    if (!dataObj || typeof dataObj !== 'object') throw new Error("INVALID_DATA_TYPE");
    if (schema) {
      const v = DataSchema_.validate(dataObj, schema);
      if (!v.valid) throw new Error("SCHEMA_VALIDATION_FAILED: " + v.errors.join(", "));
    }
    let jsonStr = JSON.stringify(dataObj);
    if (Utilities.newBlob(jsonStr).getBytes().length > DATA_SIZE_LIMIT_BYTES) throw new Error("DATA_SIZE_LIMIT_EXCEEDED_100KB");
    const encrypted = Security_.encrypt(jsonStr);
    Foundation_saveChunkedData_('APP_DATA', encrypted);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function Foundation_loadUserData() {
  try {
    const props = PropertiesService.getUserProperties();
    const encKey = props.getProperty('GEMINI_KEY');
    const apiKey = Security_.decrypt(encKey);
    const hasKey = !!(encKey && apiKey && apiKey.length > 20);
    const encData = Foundation_loadChunkedData_('APP_DATA');
    let data = null;
    if (encData) {
      const jsonStr = Security_.decrypt(encData);
      try { data = jsonStr ? JSON.parse(jsonStr) : {}; } catch(e) { data = {}; }
    }
    return { success: true, hasApiKey: hasKey, data: data || {} };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function Foundation_saveApiKey(key) {
  try {
    const k = key ? key.trim() : "";
    if (k.length < 30) throw new Error("KEY_FORMAT_INVALID");
    PropertiesService.getUserProperties().setProperty('GEMINI_KEY', Security_.encrypt(k));
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
}

function Foundation_deleteUserData(hard) {
  const props = PropertiesService.getUserProperties();
  if (!hard) {
    const backup = { data: Foundation_loadChunkedData_('APP_DATA'), key: props.getProperty('GEMINI_KEY'), deletedAt: new Date().toISOString() };
    props.setProperty('DELETED_BACKUP', JSON.stringify(backup));
    props.deleteAllProperties();
    props.setProperty('DELETED_BACKUP', JSON.stringify(backup));
    const restoreUntil = new Date(new Date().getTime() + 24*60*60*1000);
    return { success: true, mode: 'soft', restoreUntil: restoreUntil.toLocaleString('ja-JP') };
  }
  props.deleteAllProperties();
  return { success: true, mode: 'hard' };
}

function clearAllData() {
  return Foundation_deleteUserData(true);
}

// =====================================================================
// [Foundation] 4. 設定管理 (ScriptProperties / Standalone)
// =====================================================================

function getConfigSheetId_() {
  return PropertiesService.getScriptProperties().getProperty('CONFIG_SHEET_ID') || DEFAULT_CONFIG_SHEET_ID;
}

/**
 * 【管理者専用】手動更新関数
 * ※これはちゃろさんがエディタから実行する時のみ動く
 */
function adminManualUpdateConfig() {
  console.log("Starting Admin Config Update...");
  try {
    const sheetId = getConfigSheetId_();
    // スタンドアロン対応
    const ss = SpreadsheetApp.openById(sheetId);
    const sheet = ss.getSheets()[0];
    const lastRow = sheet.getLastRow();
    const lastCol = sheet.getLastColumn();
    
    if (lastRow === 0 || lastCol === 0) throw new Error("Sheet is empty");
    
    const values = sheet.getRange(1, 1, lastRow, lastCol).getValues();
    const validModels = values.flat().map(v => String(v).trim())
      .filter(v => ALLOWED_MODEL_PREFIXES.some(p => v.toLowerCase().startsWith(p)));
    
    const uniqueModels = [...new Set(validModels)];
    if (uniqueModels.length === 0) throw new Error("No valid models found");
    
    PropertiesService.getScriptProperties().setProperties({
      'GLOBAL_MODELS': JSON.stringify(uniqueModels),
      'LAST_UPDATE_TIME': new Date().getTime().toString()
    });
    
    console.log("✅ SUCCESS: Models updated in Shared Memory:", uniqueModels);
    return `Update Success: ${uniqueModels.join(", ")}`;
  } catch (e) {
    console.error("Admin Update Failed:", e);
    return `Update Failed: ${e.message}`;
  }
}

function getModelCandidates() {
  try {
    const props = PropertiesService.getScriptProperties();
    const json = props.getProperty("GLOBAL_MODELS");
    if (json) return JSON.parse(json);
    return FALLBACK_MODELS;
  } catch (e) { 
    return FALLBACK_MODELS; 
  }
}

// =====================================================================
// [Foundation] 5. AIエンジン接続
// =====================================================================

function isQuotaError_(code, errorMsg, errorStatus) {
  if (code === 429) return true;
  if (code === 403 || code === 503) {
    const keywords = ['quota', 'limit', 'rate', 'exceeded', 'exhausted'];
    if (keywords.some(kw => errorMsg.toLowerCase().includes(kw))) return true;
  }
  if (errorStatus === 'RESOURCE_EXHAUSTED') return true;
  return false;
}

function calculateQuotaResetTime_() {
  try {
    const now = new Date();
    const pstDateStr = now.toLocaleString("en-US", {timeZone: "America/Los_Angeles"});
    const pstMidnight = new Date(pstDateStr);
    pstMidnight.setDate(pstMidnight.getDate() + 1);
    pstMidnight.setHours(0, 0, 0, 0);
    const diffMs = pstMidnight.getTime() - new Date(pstDateStr).getTime();
    const localReset = new Date(now.getTime() + diffMs);
    const hoursUntil = Math.ceil(diffMs / (1000 * 60 * 60));
    return { hoursUntil, resetTimeStr: localReset.toLocaleString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) };
  } catch(e) { return { hoursUntil: 24, resetTimeStr: "明日" }; }
}

function callGeminiEngine(prompt, systemInstruction = "") {
  try {
    const encKey = PropertiesService.getUserProperties().getProperty('GEMINI_KEY');
    if (!encKey) throw new Error("NO_API_KEY");
    const apiKey = Security_.decrypt(encKey);
    if (!apiKey) throw new Error("INVALID_KEY_STORED");

    const models = getModelCandidates();
    let lastError = "";
    let allModelsQuotaError = true;

    for (const model of models) {
      if (CircuitBreaker_.isOpen(model)) continue;
      let thisModelQuota = false;

      for (let retry = 0; retry <= MAX_RETRIES; retry++) {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
        const payload = { contents: [{ parts: [{ text: prompt }] }] };
        if (systemInstruction) payload.systemInstruction = { parts: [{ text: systemInstruction }] };
        const options = { 
          method: 'post', contentType: 'application/json', 
          headers: { 'x-goog-api-key': apiKey }, 
          payload: JSON.stringify(payload), muteHttpExceptions: true, timeout: 30 
        };

        try {
          const response = UrlFetchApp.fetch(url, options);
          const code = response.getResponseCode();
          
          if (code === 200) {
            const json = JSON.parse(response.getContentText());
            const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
            if (text) {
              CircuitBreaker_.recordSuccess(model);
              return { success: true, text: text, model: model };
            }
          }
          
          const bodyText = response.getContentText();
          let errorMsg = bodyText;
          let errorStatus = "";
          try { 
            const eJson = JSON.parse(bodyText).error;
            errorMsg = eJson.message || bodyText;
            errorStatus = eJson.status;
          } catch(_){}

          if (isQuotaError_(code, errorMsg, errorStatus)) {
            thisModelQuota = true; 
            if (retry < MAX_RETRIES) {
               Utilities.sleep((RETRY_BASE_DELAY_MS * Math.pow(2, retry)) + (Math.random() * 500));
               continue; 
            } else {
               CircuitBreaker_.recordFailure(model);
            }
          } else if (code === 400 && errorMsg.includes("API_KEY_INVALID")) {
            throw new Error("INVALID_KEY_DETECTED");
          } else if (code >= 500) {
            if (retry < MAX_RETRIES) {
              Utilities.sleep((RETRY_BASE_DELAY_MS * Math.pow(2, retry)) + (Math.random() * 500));
              continue; 
            } else {
              CircuitBreaker_.recordFailure(model);
            }
          }
          lastError += `[${model}:${code}] `; break; 

        } catch (innerE) {
          if (innerE.message === "INVALID_KEY_DETECTED") throw innerE;
          lastError += `[${model}:Err] `; break; 
        }
      }
      if (!thisModelQuota) allModelsQuotaError = false;
    }

    if (allModelsQuotaError && lastError.length > 0) {
      const resetInfo = calculateQuotaResetTime_();
      return { success: false, error: "QUOTA_EXCEEDED_STRICT", resetTime: resetInfo.resetTimeStr, hoursUntil: resetInfo.hoursUntil };
    }
    throw new Error("ALL_MODELS_FAILED: " + lastError);

  } catch (e) {
    return { success: false, error: e.message, resetTime: e.resetTime, hoursUntil: e.hoursUntil };
  }
}

function Foundation_testConnection(apiKey) {
  if (!apiKey || apiKey.trim().length < 30) return { success: false, error: "KEY_FORMAT_INVALID" };
  const cleanKey = apiKey.trim();
  const candidates = getModelCandidates();
  candidates.push("gemini-1.5-flash");
  const models = [...new Set(candidates)];
  let lastError = "CONNECTION_FAILED";

  for (const model of models) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
      const payload = { contents: [{ parts: [{ text: "Hi" }] }] };
      const options = {
        method: 'post', contentType: 'application/json',
        headers: { 'x-goog-api-key': cleanKey },
        payload: JSON.stringify(payload), muteHttpExceptions: true
      };
      
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      if (code === 200) return { success: true };
      
      const body = response.getContentText();
      if (code === 400 && body.includes("API_KEY_INVALID")) return { success: false, error: "INVALID_KEY_DETECTED" };
      if (code === 429) lastError = "QUOTA_OR_RATE_LIMIT";
      else lastError = `HTTP_${code}`;
      
    } catch (e) { lastError = e.message; }
  }
  return { success: false, error: lastError };
}

// =====================================================================
// [Adapter] 恋のオラクル Logic (User-Local-DB Mode)
// =====================================================================

function doGet(e) {
  // DB初期化不要（UserPropertiesは自動生成されるため）
  return HtmlService.createHtmlOutputFromFile('Index')
    .setTitle("恋のオラクル AI恋星譚")
    .addMetaTag('viewport', 'width=device-width, initial-scale=1.0');
}

function testAndSaveApiKey(apiKey) {
  const validation = Foundation_testConnection(apiKey);
  if (validation.success) {
    const saveRes = Foundation_saveApiKey(apiKey);
    if (!saveRes.success) return { success: false, message: saveRes.error };
    return { success: true, message: "OK (Connected via Zenith)", model: "Auto-Balanced" };
  } else {
    let friendlyMessage = validation.error;
    if (validation.error === "INVALID_KEY_DETECTED") friendlyMessage = "APIキーが無効です。";
    return { success: false, message: friendlyMessage };
  }
}

function registerForEmailAnalysis(apiKey, userEmail) {
  const currentRes = Foundation_loadUserData();
  const currentData = currentRes.data || {};
  currentData.userEmail = userEmail;
  const res = Foundation_saveUserData(currentData);
  return res.success ? { success: true, message: "設定保存完了" } : { success: false, message: res.error };
}

function runDiagnosis(formData) {
  try {
    const authCheck = Foundation_loadUserData();
    if (!authCheck.hasApiKey) throw new Error("APIキーが設定されていません。");

    const [messages, _] = parseLineChat_(formData.talkData);
    if (messages.length === 0) throw new Error("有効なメッセージが見つかりませんでした。");

    const [tempData, trend] = calculateTemperature_(messages);
    const messagesSummary = smartExtractText_(messages, 8000);
    const longTermSummary = createLongTermSummary_(messages, 4000);
    
    // ★UserPropertiesから過去履歴を取得（エラーなし）
    const historyStats = getHistoryStats_("Owner", formData.partnerName);

    const finalPrompt = buildPrompt_(
      formData.character, formData.tone, formData.yourName,
      formData.partnerName, formData.counselingText,
      messagesSummary, longTermSummary, trend, 
      historyStats
    );

    const aiResponse = callGeminiEngine(finalPrompt);
    if (!aiResponse.success) {
       if (aiResponse.error === "QUOTA_EXCEEDED_STRICT") throw new Error(`API利用上限。${aiResponse.resetTime}頃回復`);
       throw new Error(aiResponse.error);
    }

    const aiResponseText = aiResponse.text;
    const pulseScore = extractPulseScoreFromResponse_(aiResponseText);
    const summary = extractSummaryFromResponse_(aiResponseText);
    
    // ★UserPropertiesに結果を保存（エラーなし・暗号化済み）
    saveDiagnosisResult_("Owner", formData.partnerName, pulseScore, summary);

    return {
      success: true,
      aiResponse: aiResponseText,
      chartData: tempData,
      pulseScore: pulseScore,
      previousScore: historyStats ? historyStats.lastScore : null
    };
  } catch (e) {
    console.error("Diagnosis Error: " + e.stack);
    return { success: false, error: e.message };
  }
}

// ---------------------------------------------------------------------
// --- PDF & Helper Logic ---
// ---------------------------------------------------------------------

function createPdfReport(aiResponseText, character, chartImageBase64) {
    try {
        const doc = DocumentApp.create(`鑑定書_${new Date().getTime()}`);
        const body = doc.getBody();
        const colors = getCharacterColors_(character);
        const SIZE_TITLE = 24; const SIZE_HEADING = 18; const SIZE_BODY = 12;    
        
        const title = body.appendParagraph("🌙 恋のオラクル AI恋星譚");
        title.setHeading(DocumentApp.ParagraphHeading.HEADING1).setAlignment(DocumentApp.HorizontalAlignment.CENTER);
        title.editAsText().setFontSize(SIZE_TITLE).setForegroundColor(colors.primary);

        const subTitle = body.appendParagraph("- 心の羅針盤 Edition -");
        subTitle.setAlignment(DocumentApp.HorizontalAlignment.CENTER).setSpacingAfter(10);
        subTitle.editAsText().setFontSize(12).setForegroundColor("#666666");

        const dateP = body.appendParagraph(`鑑定日: ${Utilities.formatDate(new Date(), "JST", "yyyy年MM月dd日")}`);
        dateP.setAlignment(DocumentApp.HorizontalAlignment.RIGHT).setSpacingAfter(10);
        dateP.editAsText().setFontSize(10).setForegroundColor("#888888");
        body.appendHorizontalRule();

        if (chartImageBase64) {
            try {
                const imageBlob = Utilities.newBlob(Utilities.base64Decode(chartImageBase64), MimeType.PNG);
                const image = body.appendImage(imageBlob);
                const width = image.getWidth(); const height = image.getHeight();
                const newWidth = 450; const newHeight = (height * newWidth) / width;
                image.setWidth(newWidth).setHeight(newHeight);
                const imgParagraph = image.getParent();
                imgParagraph.setAlignment(DocumentApp.HorizontalAlignment.CENTER);
                body.appendParagraph("");
            } catch (e) { body.appendParagraph("※グラフ生成失敗"); }
        }
        
        const lines = aiResponseText.split('\n');
        lines.forEach(line => {
            let text = line.trim();
            if (!text) { body.appendParagraph("").editAsText().setFontSize(6); return; }
            if (text.match(/^\s*#+\s+/) || text.match(/^\s*\*\*.*\*\*\s*[:：]?\s*$/)) {
                const cleanText = text.replace(/^\s*#+\s+/, '').replace(/\*\*/g, '').replace(/[:：]\s*$/, '');
                const p = body.appendParagraph(cleanText);
                p.setHeading(DocumentApp.ParagraphHeading.HEADING3).setSpacingBefore(16).setSpacingAfter(6).setLineSpacing(1.15);
                p.editAsText().setFontSize(SIZE_HEADING).setForegroundColor(colors.primary).setBold(true);
            } else {
                let p; let cleanText = text;
                if (text.match(/^\s*([\*\-・]|\d+\.)\s+/)) {
                    cleanText = text.replace(/^\s*([\*\-・]|\d+\.)\s+/, '');
                    p = body.appendParagraph("・" + cleanText);
                    p.setIndentStart(20).setIndentFirstLine(0);
                } else { p = body.appendParagraph(cleanText); }
                p.setSpacingAfter(6).setLineSpacing(1.5);
                applyBoldHighlight_(p, cleanText, colors.highlight);
                const textObj = p.editAsText();
                textObj.setFontSize(SIZE_BODY).setForegroundColor(colors.text);
            }
        });
        doc.saveAndClose();
        const base64Pdf = Utilities.base64Encode(doc.getAs(MimeType.PDF).getBytes());
        DriveApp.getFileById(doc.getId()).setTrashed(true);
        return base64Pdf;
    } catch (e) { throw new Error("PDF生成失敗"); }
}

function getCharacterColors_(character) {
    if (character && character.includes("ロジカル")) return { primary: "#1e90ff", highlight: "#e6f2ff", text: "#333333" };
    if (character && character.includes("ミステリアス")) return { primary: "#9370db", highlight: "#f3e6ff", text: "#333333" };
    return { primary: "#ff69b4", highlight: "#ffe6f0", text: "#333333" };
}

function applyBoldHighlight_(paragraph, text, highlightColor) {
    const parts = text.split(/\*\*/);
    if (parts.length === 1) { paragraph.setText(text.replace(/\*\*/g, '')); return; }
    const cleanText = text.replace(/\*\*/g, '');
    paragraph.setText(cleanText);
    let currentIndex = 0;
    for (let i = 0; i < parts.length; i++) {
        const partLen = parts[i].length;
        if (i % 2 === 1 && partLen > 0) {
            const start = currentIndex;
            const end = currentIndex + partLen - 1;
            paragraph.editAsText().setBold(start, end, true).setBackgroundColor(start, end, highlightColor);
        }
        currentIndex += partLen;
    }
}

// ---------------------------------------------------------------------
// --- 内部ロジック (Full Prompt & Local DB Logic) ---
// ---------------------------------------------------------------------

function parseLineChat_(textData) {
  const lines = textData.trim().split('\n');
  let messages = [], currentDate = "日付不明";
  const filteredLines = lines.filter(line => !(line.startsWith('[') && line.endsWith(']')));
  const messagePattern = /^(\d{1,2}:\d{2})\t([^\t]+)\t(.*)/;
  for (const line of filteredLines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;
    const dateMatch = trimmedLine.match(/^\d{4}\/\d{2}\/\d{2}\(.\)/);
    if (dateMatch) { currentDate = dateMatch[0]; continue; }
    const messageMatch = trimmedLine.match(messagePattern);
    if (messageMatch) {
      try {
        const [, time, sender, message] = messageMatch;
        if (!["[写真]", "[動画]", "[スタンプ]", "[ファイル]"].includes(message.trim())) {
          messages.push({'timestamp': `${currentDate} ${time}`,'sender': sender.trim(),'message': message.trim()});
        }
      } catch (e) {}
      continue;
    }
    if (messages.length > 0) { messages[messages.length - 1].message += '\n' + trimmedLine; }
  }
  return [messages, ""];
}

function smartExtractText_(messages, maxChars = 8000) {
    const textLines = messages.map(msg => `${msg.sender}: ${msg.message}`);
    const fullText = textLines.join("\n");
    if (fullText.length <= maxChars) return fullText;
    let truncatedText = "";
    for (let i = textLines.length - 1; i >= 0; i--) {
        if (truncatedText.length + textLines[i].length > maxChars) break;
        truncatedText = textLines[i] + "\n" + truncatedText;
    }
    return truncatedText;
}

function createLongTermSummary_(messages, maxChars = 4000) {
    const textLines = messages.map(msg => `${msg.sender}: ${msg.message}`);
    if (textLines.length === 0) return "データなし";
    const fullText = textLines.join("\n");
    if (fullText.length <= maxChars) return fullText;
    let summary = [];
    const totalLines = textLines.length;
    const partSize = Math.floor(totalLines / 3);
    const charsPerPart = Math.floor(maxChars / 3);
    summary.push("--- 初期 ---\n" + textLines.slice(0, partSize).join("\n").substring(0, charsPerPart));
    summary.push("--- 中期 ---\n" + textLines.slice(partSize, partSize * 2).join("\n").substring(0, charsPerPart));
    summary.push("--- 後期 ---\n" + textLines.slice(partSize * 2).join("\n").substring(0, charsPerPart));
    return summary.join("\n\n");
}

function calculateTemperature_(messages) {
    let dailyScores = {};
    for (const msg of messages) {
        try {
            const dateStr = msg.timestamp.split(' ')[0].replace(/\(.\)/, '');
            const dateObj = new Date(dateStr);
            if (isNaN(dateObj.getTime())) continue;
            const monthDay = Utilities.formatDate(dateObj, "JST", "MM/dd");
            const score = msg.message.length + (msg.message.split('!').length - 1) * 2 + (msg.message.split('？').length - 1) * 2;
            dailyScores[monthDay] = (dailyScores[monthDay] || 0) + score;
        } catch (e) {}
    }
    if (Object.keys(dailyScores).length === 0) return [{}, "データ不足"];
    const sortedScores = Object.entries(dailyScores).sort((a, b) => a[0].localeCompare(b[0]));
    const labels = sortedScores.map(item => item[0]);
    const values = sortedScores.map(item => item[1]);
    let trend = "安定";
    if (values.length >= 4) {
        const lastAvg = values.slice(-3).reduce((a, b) => a + b, 0) / 3;
        const prevValues = values.slice(0, -3);
        const prevAvg = prevValues.length > 0 ? prevValues.reduce((a, b) => a + b, 0) / prevValues.length : 0;
        if (prevAvg > 0 && lastAvg > prevAvg * 1.2) trend = "上昇傾向";
        else if (prevAvg > 0 && lastAvg < prevAvg * 0.8) trend = "下降傾向";
    }
    return [{ labels, values }, trend];
}

function buildPrompt_(character, tone, yourName, partnerName, counselingText, messagesSummary, longTermSummary, trend, historyStats) {
    const characterMap = {
        "1. 優しく包み込む、お姉さん系": ["優しく包み込むお姉さんタイプの鑑定師", "碧月（みつき）"],
        "2. ロジカルに鋭く分析する、専門家系": ["ロジカルに鋭く分析する専門家タイプの鑑定師", "詩音（しおん）"],
        "3. 星の言葉で語る、ミステリアスな占い師系": ["星の言葉で語るミステリアスな占い師", "セレスティア"]
    };
    const [charInfo, charName] = characterMap[character] || [character, "AI鑑定師"];
    
    const toneInstruction = {
        "癒し 100%": `
            【重要指示：徹底的な共感と全肯定】
            ・論理的な正しさよりも、ユーザーの感情に寄り添うことを最優先してください。
            ・否定的な言葉や厳しい指摘は一切禁止です。たとえ悪いデータがあっても、「それは伸びしろだね」「これから良くなるサインだよ」とポジティブに変換してください。
            ・文体は非常に柔らかく、母性や包容力を感じさせるものにしてください。
            ・絵文字（🌸、✨、🌙、💕など）を多めに使い、視覚的にも温かさを演出してください。
            ・まるで親友や優しい家族が、背中をさすってくれているような雰囲気で語りかけてください。
        `,
        "癒し 50% × 論理 50%": `
            【重要指示：優しさと客観性のベストバランス】
            ・ユーザーの気持ちを受け止めつつ（癒やし）、プロとして必要なアドバイス（論理）もしっかり伝えてください。
            ・まずは共感から入り、その後に「でも、データを見るとこういう傾向もあるから、こうするともっと良くなるよ」と導く構成にしてください。
            ・厳しすぎず、甘やかしすぎず、頼れるアドバイザーとしての信頼感を重視してください。
        `,
        "冷静にロジカル": `
            【重要指示：データ重視・感情論の排除】
            ・曖昧な慰めや精神論は不要です。数値と事実に基づいた、具体的で鋭い分析を提示してください。
            ・「なんとなく」ではなく「会話のこの部分から、心理学的にこう分析できる」という根拠を明確にしてください。
            ・厳しい結果が出ても隠さず、事実として伝えた上で、「ではどうすれば改善できるか」という戦略的アドバイスを行ってください。
            ・文体は理知的で、無駄を省いたスマートな表現を心がけてください。絵文字は控えめにしてください。
        `
    };
    let prompt = `あなたは【${charInfo}】の**${charName}**です。導入部分で「こんにちは、鑑定師の${charName}よ。」のように、必ず自分の名前をはっきりと名乗ってから会話を始めてください。ユーザーは【${tone}】のスタイルでの鑑定を望んでいます。${toneInstruction[tone] || ''} このトーンと言葉遣いを、出力の最後まで徹底して維持してください。**重要: あなたは鑑定の最初から最後まで、キャラクターの口調・語尾・ニュアンスを完全に一定に保ち、文体が途中で絶対に変化しないよう、強く意識してください。**以下のデータを基に、単なる占いではない、心理分析に基づいた詳細な「恋の心理レポート」を作成してください。\n\n# ユーザー情報\n- ユーザー名: ${yourName}\n- 相手の名前: ${partnerName}\n- ユーザーの悩み: ${counselingText}\n`;
    
    let comparisonInstruction = "";
    if (historyStats) {
        const prevScore = historyStats.lastScore;
        const avgScore = historyStats.averageScore;
        const count = historyStats.count;
        const lastDate = Utilities.formatDate(new Date(historyStats.lastDate), "JST", "yyyy/MM/dd");
        prompt += `\n# 過去の鑑定データ\n- これまでの鑑定回数: ${count}回\n- 前回の鑑定日: ${lastDate}\n- **前回の脈あり度: ${prevScore}%**\n- **これまでの平均脈あり度: ${avgScore}%**\n`;
        comparisonInstruction = `   **【前回・平均との比較】**: \n   - 前回の脈あり度(${prevScore}%)と比較し、「前回からどう変化したか」を必ず伝えてください。\n   - また、**これまでの平均値(${avgScore}%)**にも言及し、「普段と比べてどういう状態か」を分析して、長期的な視点でアドバイスしてください。`;
    }

    prompt += `\n# 基本データ分析\n- 会話の温度グラフの傾向: ${trend}\n\n# 関係性の歴史（全期間のダイジェスト）\n${longTermSummary}\n\n# 直近の詳細な会話（分析対象）\n${messagesSummary}\n\n\n# AIによる深層分析依頼\n1. **感情の波の分析**: トーク履歴全体を通して、「ポジティブ」「ネガティブ」な感情表現は、それぞれどのような傾向で推移していますか？\n2. **脈ありシグナルのスコア化**: 以下の項目を0〜10点で評価し、総合的な「脈あり度」をパーセンテージで算出してください。 (質問返しの積極性, ポジティブな絵文字・表現の使用頻度, 返信間隔の安定性・速さ, 相手からの賞賛・共感の言葉, 会話を広げようとする意図)\n   **【絶対厳守】出力形式:** 以下の形式を絶対に守ってください。他の表現は一切使わず、数値は太字（**）にしないでください。\n   【総合脈あり度】: 80%\n   （上記の例のように、必ず「【総合脈あり度】: 数字%」の形式で出力してください）\n${comparisonInstruction}\n   - なぜそのスコアになったのか、根拠を優しく解説してください。\n3. **相手の"隠れ心理"抽出**: 会話の中から、相手が特に「大切にしている価値観」や「本音だと感じられる発言」を3つ抜粋し、解説してください。\n4. **コミュニケーション相性診断**: 二人の言葉遣いや会話のテンポから、コミュニケーションのスタイルを分析し、「〇〇で繋がりを深めるタイプ」といった形で相性を診断してください。\n5. **「最高の瞬間」ハイライト**: このトーク履歴の中で、二人の心が最も通い合ったと感じられる瞬間を1つ選び出し、その時の会話の素晴らしい点を解説してください。\n6. **恋の未来予測**: これまでの会話データと心理分析に基づき、二人の関係性がポジティブに進展するための、心理学的な観点からの**優しい未来予測**を記述してください。\n7. **恋の処方箋・アクションチェックリスト**: 以下の4項目について、具体的かつ実践的なアドバイスを箇条書き（**マークダウンの「*」や「-」は使わず、行頭は全角の「・」を使用**）で作成してください。(今日送ると効果的なメッセージ例:（★★1つにつき80文字以内で、最大3つ★★）, 相手のタイプ別・心に刺さるキーワード, 今は控えるべきNG行動, 次回鑑定のおすすめタイミング)\n\n# 最終出力\n上記の分析結果をすべて含め、以下の構成でレポートを作成してください。\n- 導入文, **恋の温度グラフの解説**, 総合脈あり度と、その理由, 恋の心理レポート, 「最高の瞬間」の振り返り, **恋の未来予測**, **恋の処方箋・アクションチェックリスト**, ユーザーへのケアメッセージ, 最後に、温かく励ます一言\n重要: 必ず日本語で、${yourName}さんに語りかけるような親しみやすい文体で書いてください。出力は最大8000文字以内に抑えてください。\n`;
    return prompt;
}

function extractPulseScoreFromResponse_(aiResponse) {
    const match = aiResponse.match(/脈あり度[^\d]*(\d{1,3})/);
    return match ? parseInt(match[1], 10) : 0;
}

function extractSummaryFromResponse_(aiResponse) {
    return aiResponse.substring(0, 150) + "...";
}

// ---------------------------------------------------------------------
// --- ★UserProperties DB関数 (Safe Mode) ---
// ---------------------------------------------------------------------

function saveDiagnosisResult_(userId, partnerName, pulseScore, summary) {
  try {
    const res = Foundation_loadUserData();
    let data = res.data || {};
    if (!data.history) data.history = [];
    
    // 新しい履歴を追加 (暗号化はFoundation保存時に自動で行われる)
    data.history.push({
      date: new Date().toISOString(),
      partnerName: partnerName,
      score: pulseScore,
      summary: summary
    });
    
    Foundation_saveUserData(data);
  } catch (e) { console.error("Save Local DB Failed:", e); }
}

function getHistoryStats_(userId, partnerName) {
  try {
    const res = Foundation_loadUserData();
    const data = res.data || {};
    const history = data.history || [];
    
    // 相手の名前でフィルタリング
    const targetLogs = history.filter(h => h.partnerName === partnerName);
    if (targetLogs.length === 0) return null;
    
    // 日付順にソート (古い順)
    targetLogs.sort((a,b) => new Date(a.date) - new Date(b.date));
    
    const lastLog = targetLogs[targetLogs.length - 1];
    const sum = targetLogs.reduce((acc, cur) => acc + cur.score, 0);
    const avg = Math.round(sum / targetLogs.length);
    
    return {
      lastDate: lastLog.date,
      lastScore: lastLog.score,
      averageScore: avg,
      count: targetLogs.length
    };
  } catch (e) { 
    console.error("Get History Stats Failed:", e);
    return null; 
  }
}

// ---------------------------------------------------------------------
// --- メール検索 (完全維持) ---
// ---------------------------------------------------------------------
function fetchHistoryFromGmail(dummyEmail) {
  try {
    const threads = GmailApp.search('has:attachment newer_than:1d', 0, 20);
    if (!threads || threads.length === 0) return { success: false, message: "過去24時間以内の添付ファイル付きメールが見つかりません。" };
    let targetMessage = null; let targetThread = null;
    for (const thread of threads) {
        const msgs = thread.getMessages();
        const latest = msgs[msgs.length - 1];
        const attachments = latest.getAttachments();
        for (const att of attachments) {
            if (att.getName().startsWith("[LINE]") && att.getName().endsWith(".txt")) {
                targetMessage = latest; targetThread = thread; break;
            }
        }
        if (targetMessage) break;
    }
    if (!targetMessage) return { success: false, message: "メールは見つかりましたが、LINE履歴ファイル(.txt)がありません。" };
    const talkData = targetMessage.getAttachments()[0].getDataAsString();
    try { targetThread.moveToTrash(); } catch(e){}
    return { success: true, text: talkData };
  } catch (e) { return { success: false, message: "エラー: " + e.message }; }
}
