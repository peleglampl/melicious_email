// ──────────────────────────────────────────────
//  Malicious Email Scorer — Apps Script Add-on
// ──────────────────────────────────────────────
var BACKEND_URL = "https://trustee-catsup-clang.ngrok-free.dev/analyze";



// Called when the user opens an email with the add-on active
function onGmailMessageOpen(e) {
  var accessToken = e.messageMetadata.accessToken;
  var messageId   = e.messageMetadata.messageId;

  GmailApp.setCurrentMessageAccessToken(accessToken);

  var message = GmailApp.getMessageById(messageId);
  var payload = extractPayload(message);

  var result  = callBackend(payload);
  return buildCard(result, payload);
}

// ── Feature extraction ─────────────────────────────────────────────────────

function extractPayload(message) {
  var userName = getUserName();
  var bodyText = message.getPlainBody().substring(0, 2000);
  var from    = message.getFrom();
  var headers = getHeaders(message);
  var domain  = extractDomain(from);
  var history = domainHistory(domain);  // ← call once, reuse

  return {
    message_id:                   message.getId(),
    sender_email:                 from,
    sender_domain:                domain,
    reply_to:                     headers["Reply-To"]    || null,
    return_path:                  headers["Return-Path"] || null,
    subject:                      message.getSubject(),
    body_text:                    message.getPlainBody().substring(0, 2000),
    links:                        extractLinks(message.getBody()),
    spf_result:                   parseAuthHeader(headers["Authentication-Results"], "spf"),
    dkim_result:                  parseAuthHeader(headers["Authentication-Results"], "dkim"),
    dmarc_result:                 parseAuthHeader(headers["Authentication-Results"], "dmarc"),
    x_mailer:                     headers["X-Mailer"] || null,
    date_sent:                    message.getDate().toISOString(),
    prior_contact:                hasPriorContact(from),
    is_in_contacts:               isInContacts(from),
    domain_thread_count:          history.threadCount,      // ← reuse
    is_first_contact_from_domain: history.isFirstContact,   // ← reuse
    name_mismatch: checkNameMismatch(bodyText, userName),

  };
}

function getHeaders(message) {
  // Apps Script exposes raw headers via GmailApp advanced service
  var rawHeaders = {};
  try {
    var details = Gmail.Users.Messages.get("me", message.getId(), {format: "metadata"});
    details.payload.headers.forEach(function(h) {
      rawHeaders[h.name] = h.value;
    });
  } catch (err) {
    Logger.log("Header fetch error: " + err);
  }
  return rawHeaders;
}

function extractDomain(email) {
  var match = email.match(/@([\w.\-]+)/);
  return match ? match[1].toLowerCase() : email.toLowerCase();
}

function extractLinks(htmlBody) {
  var links = [];
  var regex  = /href=["'](https?:\/\/[^"']+)["']/gi;
  var match;
  while ((match = regex.exec(htmlBody)) !== null) {
    links.push(match[1]);
    if (links.length >= 20) break; // cap at 20
  }
  return links;
}

function parseAuthHeader(header, protocol) {
  if (!header) return null;
  var regex = new RegExp(protocol + "=([\\w]+)", "i");
  var match = header.match(regex);
  return match ? match[1].toLowerCase() : null;
}

// ── Backend call ──────────────────────────────────────────────────────────

function callBackend(payload) {
  var options = {
    method:      "post",
    contentType: "application/json",
    payload:     JSON.stringify(payload),
    muteHttpExceptions: true,
    headers: {
      "ngrok-skip-browser-warning": "true"
    }
  };

  try {
    var response = UrlFetchApp.fetch(BACKEND_URL, options);
    var text = response.getContentText();
    Logger.log("Response code: " + response.getResponseCode());
    Logger.log("Response body: " + text);  // ← see exactly what comes back
    return JSON.parse(text);
  } catch (err) {
    return { error: err.toString() };
  }
}
// ── Card UI ───────────────────────────────────────────────────────────────

function buildCard(result, payload) {
  var card    = CardService.newCardBuilder().setName("Email Risk Analysis");
  var section = CardService.newCardSection().setHeader("Risk Analysis");

  if (result.error) {
    section.addWidget(
      CardService.newTextParagraph().setText("⚠️ Backend error: " + result.error)
    );
    return card.addSection(section).build();
  }

  var verdictEmoji = { safe: "✅", suspicious: "⚠️", phishing: "🚨" }[result.verdict] || "❓";

  // Score header
  section.addWidget(
    CardService.newTextParagraph().setText(
      "<b>" + verdictEmoji + " " + result.verdict.toUpperCase() + "</b> — Score: " +
      result.total_score + "/100 (Confidence: " + result.confidence + ")"
    )
  );

  // Recommendation
  section.addWidget(
    CardService.newTextParagraph().setText(result.recommendation)
  );

  // Signal breakdown
  if (result.signals && result.signals.length > 0) {
    var sigSection = CardService.newCardSection().setHeader("Signal Breakdown");
    result.signals.forEach(function(sig) {
      var icon = { low: "🟡", medium: "🟠", high: "🔴" }[sig.severity] || "⚪";
      sigSection.addWidget(
        CardService.newTextParagraph().setText(
          icon + " <b>" + sig.name + "</b> (+" + sig.score + " pts)<br>" + sig.description
        )
      );
    });
    return card.addSection(section).addSection(sigSection).build();
  }

  return card.addSection(section).build();
}

// In Code.gs
function hasPriorContact(senderEmail) {
  var threads = GmailApp.search('from:' + senderEmail, 0, 1);
  var sentThreads = GmailApp.search('to:' + senderEmail, 0, 1);
  return threads.length > 0 || sentThreads.length > 0;
}

function isInContacts(senderEmail) {
  try {
    var contacts = ContactsApp.getContactsByEmailAddress(senderEmail);
    return contacts.length > 0;
  } catch(e) {
    Logger.log("ContactsApp error: " + e);
    return false;  // fail safe — don't crash if contacts unavailable
  }
}

function domainHistory(senderDomain) {
  var threads = GmailApp.search('from:@' + senderDomain, 0, 5);
  return {
    threadCount: threads.length,
    isFirstContact: threads.length <= 1  // only this email
  };
}

function getUserFullName() {
  try {
    var email = Session.getActiveUser().getEmail();
    var name = Session.getActiveUser().getEmail();
    // Get name from Gmail profile
    var profile = Gmail.Users.getProfile('me');
    return profile.emailAddress.split('@')[0].toLowerCase();
  } catch(e) {
    return null;
  }
}

function getUserName() {
  try {
    var aboutData = Gmail.Users.getProfile('me');
    return aboutData.emailAddress.split('@')[0].toLowerCase();
  } catch(e) {
    return null;
  }
}

function checkNameMismatch(bodyText, userName) {
  if (!userName || !bodyText) return false;

  // Look for "Dear X" or "Hi X" patterns
  var match = bodyText.match(/(?:dear|hi|hello|hey)\s+(\w+)/i);
  if (!match) return false;

  var addressedName = match[1].toLowerCase();

  // If addressed name doesn't match username at all
  return addressedName !== userName &&
         !userName.includes(addressedName) &&
         !addressedName.includes(userName);
}
