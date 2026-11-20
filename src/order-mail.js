"use strict";

const nodemailer = require("nodemailer");
const crypto = require("crypto");
const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");

const FROM_ADDRESS = String(process.env.SMTP_FROM || process.env.SMTP_USER || "supplypanel@notifications.bendemen.com").trim();
const REPLY_TO = String(process.env.SMTP_REPLY_TO || "").trim();
let smtpTransporter = null;

function configured() {
  return Boolean(
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS
  );
}

function transporter() {
  if (!configured()) throw new Error("SMTP configuratie ontbreekt (SMTP_HOST, SMTP_USER, SMTP_PASS of PANEL_PUBLIC_URL).");
  if (smtpTransporter) return smtpTransporter;
  const port = Number(process.env.SMTP_PORT || 465);
  const secure = process.env.SMTP_SECURE === undefined
    ? port === 465
    : String(process.env.SMTP_SECURE).toLowerCase() === "true";
  smtpTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    connectionTimeout: 20000,
    greetingTimeout: 20000,
    socketTimeout: 30000
  });
  return smtpTransporter;
}

async function verifySmtpConnection() {
  const smtp = transporter();
  await smtp.verify();
  return {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: process.env.SMTP_SECURE === undefined
      ? Number(process.env.SMTP_PORT || 465) === 465
      : String(process.env.SMTP_SECURE).toLowerCase() === "true",
    user: process.env.SMTP_USER,
    from: FROM_ADDRESS
  };
}

function makePdf(order) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 48 });
    const chunks = [];
    doc.on("data", chunk => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
    doc.fontSize(20).text("Bendemen Studios");
    doc.moveDown().fontSize(14).text("Pro-forma betalingsverzoek");
    doc.moveDown().fontSize(10).text(`Bestelling #${order.number || order.id}`);
    for (const item of order.line_items || []) {
      doc.text(`${item.name} × ${item.quantity}`);
    }
    doc.moveDown().fontSize(12).text(`Totaal: ${order.total || ""} ${order.currency || ""}`);
    doc.moveDown().fontSize(9).text("Dit document is een pro-forma betalingsverzoek en geen definitieve btw-factuur.");
    doc.end();
  });
}

function orderUrl(order, isTest) {
  const base = String(process.env.PANEL_PUBLIC_URL || "").replace(/\/$/, "");
  if (isTest || !order.user_id || !process.env.SESSION_SECRET) {
    return isTest ? base + "/orders" : base + "/orders/" + encodeURIComponent(order.id);
  }
  const claims = {
    user_id: Number(order.user_id),
    order_id: Number(order.id),
    nonce: crypto.randomBytes(24).toString("hex"),
    exp: Math.floor(Date.now() / 1000) + 5 * 24 * 60 * 60,
  };
  const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(encoded).digest("hex");
  return base + "/email-login?token=" + encodeURIComponent(encoded + "." + signature);
}

function emailLayout(content, includeImages = true) {
  return `<!doctype html>
<html lang="nl">
  <body style="margin:0;padding:24px 12px;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#20242a;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:0 auto;background:#ffffff;border-collapse:collapse;">
      ${includeImages ? '<tr><td style="padding:0;"><img src="cid:bendemen-mail-header" width="500" alt="Bendemen Studios" style="display:block;width:100%;max-width:500px;height:auto;border:0;margin:0 auto;"></td></tr>' : ''}
      <tr><td style="padding:28px 30px;line-height:1.6;font-size:15px;">${content}</td></tr>
      ${includeImages ? '<tr><td style="padding:0;"><img src="cid:bendemen-mail-footer" width="500" alt="Bendemen Studios" style="display:block;width:100%;max-width:500px;height:auto;border:0;margin:0 auto;"></td></tr>' : ''}
    </table>
  </body>
</html>`;
}

function imageAttachments() {
  const publicDir = path.join(__dirname, "..", "public");
  return [
    { filename: "automailheader.png", path: path.join(publicDir, "automailheader.png"), cid: "bendemen-mail-header" },
    { filename: "automailfooter.png", path: path.join(publicDir, "automailfooter.png"), cid: "bendemen-mail-footer" }
  ];
}
function escapeHtml(value) {
  return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// Centrale verzendlaag: iedere e-mail krijgt dezelfde huisstijl en inline header/footer.
function sendBrandedMail(options) {
  const html = String(options.html || "");
  const brandedHtml = /<img[^>]+cid:bendemen-mail-(?:header|footer)/i.test(html)
    ? html
    : emailLayout(html);
  const existingAttachments = Array.isArray(options.attachments) ? options.attachments : [];
  const imageCids = new Set(existingAttachments.map(item => item && item.cid).filter(Boolean));
  const brandImages = imageAttachments().filter(item => !imageCids.has(item.cid));
  const text = String(options.text || "").trim();
  const brandedText = text + (text ? "\\n\\n" : "") +
    "Met vriendelijke groet,\\nTeam Bendemen\\nBendemen Studios\\ninfo@bendemen.nl";
  return transporter().sendMail({
    ...options,
    text: brandedText,
    html: brandedHtml,
    attachments: [...existingAttachments, ...brandImages]
  });
}

function sender(displayName) {
  return { name: displayName, address: FROM_ADDRESS };
}

function mailHeaders() {
  return REPLY_TO ? { replyTo: REPLY_TO } : {};
}

async function sendAutomatedOrderEmail({ to, order, isTest = false }) {
  const url = orderUrl(order, isTest);
  const attachments = imageAttachments();
  const number = order.number || order.id;
  const total = order.total
    ? new Intl.NumberFormat("nl-NL", { style: "currency", currency: order.currency || "EUR" }).format(Number(order.total))
    : "";
  const paymentLine = "Wij verzoeken u vriendelijk om het openstaande bedrag binnen 14 dagen te voldoen.";
  const items = (order.line_items || []).map(item => ({
    name: String(item.name || "Product"),
    quantity: Number(item.quantity || 1)
  }));
  const itemText = items.length
    ? ["Bestelde producten:", ...items.map(item => "- " + item.name + " × " + item.quantity)]
    : [];
  const text = [
    "Bendemen Studios",
    "",
    "Beste klant,",
    "",
    "Uw factuur voor bestelling " + number + " staat klaar om betaald te worden.",
    total ? "Het factuurbedrag is " + total + "." : "",
    "",
    ...itemText,
    "",
    "Bekijk uw bestelling en betaal veilig via deze link:",
    url,
    "",
    paymentLine,
    "",
    "Heeft u vragen over deze factuur of de betaling? Mail ons via info@bendemen.nl.",
    "",
    "Met vriendelijke groet,",
    "Team Bendemen"
  ].filter(line => line !== "").join("\n");
  const html = emailLayout(
    '<p>Beste klant,</p>' +
    '<p>Uw factuur voor bestelling <strong>' + escapeHtml(number) + '</strong> staat klaar om betaald te worden.</p>' +
    (total ? '<p>Het factuurbedrag bedraagt <strong>' + escapeHtml(total) + '</strong>.</p>' : '') +
    (items.length ? '<p><strong>Overzicht van uw bestelling:</strong></p><ul>' + items.map(item => '<li>' + escapeHtml(item.name) + ' × ' + escapeHtml(item.quantity) + '</li>').join('') + '</ul>' : '') +
    '<p>Via uw persoonlijke bestelomgeving kunt u de bestelling bekijken, de factuurgegevens controleren en de betaling veilig afronden.</p>' +
    '<p style="margin:26px 0;text-align:center;"><a href="' + escapeHtml(url) + '" style="display:inline-block;padding:14px 26px;background:#20242a;color:#ffffff;text-decoration:none;border-radius:5px;font-weight:bold;">Bekijk en betaal uw factuur</a></p>' +
    '<p style="font-size:13px;color:#555555;">Werkt de knop niet? Kopieer dan deze link en open deze in uw browser:<br><a href="' + escapeHtml(url) + '">' + escapeHtml(url) + '</a></p>' +
    '<p><strong>Betalingstermijn</strong><br>' + paymentLine + '</p>' +
    '<p>Na het openen van uw persoonlijke bestelpagina kunt u de beschikbare betaalmethode kiezen. Bewaar deze e-mail voor uw administratie.</p>' +
    '<p>Heeft u vragen over deze factuur of de betaling? Neem dan gerust contact met ons op via <a href="mailto:info@bendemen.nl" style="color:#20242a;text-decoration:underline;">info@bendemen.nl</a>.</p>' +
    '<p>Met vriendelijke groet,<br><strong>Team Bendemen</strong></p>'
  );
  return sendBrandedMail({
    from: sender("Factuur klaar om te betalen | Bendemen"),
    ...mailHeaders(),
    to,
    envelope: { from: FROM_ADDRESS, to: [to] },
    headers: { "X-Mailer": "Bendemen Supply Panel" },
    subject: `Uw factuur staat klaar – bestelling #${number}${isTest ? " (test)" : ""}`,
    text,
    html,
    attachments
  });
}

async function sendScheduledOrderReminder({ to, order, daysBefore, orderDate, isTest = false }) {
  const url = orderUrl(order, isTest);
  const date = new Intl.DateTimeFormat("nl-NL", {
    dateStyle: "long",
    timeZone: process.env.BUSINESS_TIME_ZONE || "Europe/Amsterdam"
  }).format(new Date(orderDate + "T12:00:00Z"));
  const subject = daysBefore === 7
    ? "Herinnering: je bestelling staat over 7 dagen gepland"
    : "Laatste herinnering: je bestelling staat over 3 dagen gepland";
  const text = `Je geplande bestelling staat gepland op ${date}. Bekijk de bestelling in het Bendemen Supply Panel: ${url}`;
  return sendBrandedMail({
    from: sender(`${daysBefore} dagen nog om te betalen | Bendemen Supply Panel`),
    ...mailHeaders(),
    to,
    envelope: { from: FROM_ADDRESS, to: [to] },
    headers: { "X-Mailer": "Bendemen Supply Panel" },
    subject: subject + (isTest ? " (test)" : ""),
    text,
    attachments: imageAttachments(),
    html: emailLayout(`<p>Dit is een herinnering voor je geplande bestelling.</p><p>De bestelling staat gepland op <strong>${date}</strong> (over ${daysBefore} dagen).</p><p><a href="${url}" style="display:inline-block;padding:12px 18px;background:#20242a;color:#ffffff;text-decoration:none;border-radius:4px;">Bekijk je bestelling in het Bendemen Supply Panel</a></p><p>Heb je vragen? Neem dan contact met ons op.</p>`)
  });
}


async function sendSecurityCodeEmail({ to, code, purpose = "login" }) {
  const setup = purpose === "setup";
  const intro = setup ? "Gebruik deze code om e-mailverificatie voor je Supply Panel-account in te schakelen." : "Gebruik deze code om in te loggen op je Supply Panel-account.";
  return sendBrandedMail({
    from: sender("Beveiliging | Bendemen Supply Panel"), ...mailHeaders(), to,
    envelope: { from: FROM_ADDRESS, to: [to] },
    headers: { "X-Mailer": "Bendemen Supply Panel" },
    subject: (setup ? "Beveiligingscode instellen" : "Je inlogcode") + " | Bendemen Supply Panel",
    text: intro + "\n\nJe code: " + code + "\n\nDe code is 10 minuten geldig. Deel deze code met niemand.",
    html: emailLayout("<p>" + intro + "</p><p style=\"font-size:28px;font-weight:bold;letter-spacing:8px\">" + code + "</p><p>De code is 10 minuten geldig. Deel deze code met niemand.</p>")
  });
}

module.exports = {
  sendSecurityCodeEmail,
  sendAutomatedOrderEmail,
  sendScheduledOrderReminder,
  makePdf,
  configured,
  verifySmtpConnection
};
