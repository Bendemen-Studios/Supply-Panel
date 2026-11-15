"use strict";

const nodemailer = require("nodemailer");
const crypto = require("crypto");
const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");

const FROM_ADDRESS = String(process.env.SMTP_USER || process.env.SMTP_FROM || "supplypanel@notifications.bendemen.com").trim();
const REPLY_TO = String(process.env.SMTP_REPLY_TO || "").trim();
let smtpTransporter = null;

function configured() {
  return Boolean(
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS &&
    process.env.PANEL_PUBLIC_URL
  );
}

function transporter() {
  if (!configured()) throw new Error("SMTP configuratie ontbreekt (SMTP_HOST, SMTP_USER, SMTP_PASS of PANEL_PUBLIC_URL).");
  if (smtpTransporter) return smtpTransporter;
  smtpTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE || "true") === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    connectionTimeout: 20000,
    greetingTimeout: 20000,
    socketTimeout: 30000
  });
  return smtpTransporter;
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
  };
  const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(encoded).digest("hex");
  return base + "/email-login?token=" + encodeURIComponent(encoded + "." + signature);
}

function emailLayout(content) {
  return `<!doctype html>
<html lang="nl">
  <body style="margin:0;padding:24px 12px;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#20242a;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:0 auto;background:#ffffff;border-collapse:collapse;">
      <tr><td style="padding:0;"><img src="cid:bendemen-mail-header" width="500" alt="Bendemen Studios" style="display:block;width:100%;max-width:500px;height:auto;border:0;margin:0 auto;"></td></tr>
      <tr><td style="padding:28px 30px;line-height:1.6;font-size:15px;">${content}</td></tr>
      <tr><td style="padding:0;"><img src="cid:bendemen-mail-footer" width="500" alt="Bendemen Studios" style="display:block;width:100%;max-width:500px;height:auto;border:0;margin:0 auto;"></td></tr>
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
function sender(displayName) {
  return { name: displayName, address: FROM_ADDRESS };
}

function mailHeaders() {
  return REPLY_TO ? { replyTo: REPLY_TO } : {};
}

async function sendAutomatedOrderEmail({ to, order, isTest = false }) {
  const url = orderUrl(order, isTest);
  const attachments = imageAttachments();
  return transporter().sendMail({
    from: sender("Factuur aangemaakt | Bendemen Supply Panel"),
    ...mailHeaders(),
    to,
    envelope: { from: FROM_ADDRESS, to: [to] },
    headers: { "X-Mailer": "Bendemen Supply Panel" },
    subject: `Bendemen Studios – bestelling #${order.number || order.id}${isTest ? " (test)" : ""}`,
    text: `Je bestelling staat klaar. Bekijk de bestelling in het Bendemen Supply Panel: ${url}`,
    html: emailLayout(`<p>Je bestelling staat klaar.</p><p><a href="${url}" style="display:inline-block;padding:12px 18px;background:#20242a;color:#ffffff;text-decoration:none;border-radius:4px;">Bekijk bestelling en betaal veilig</a></p>`),
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
  return transporter().sendMail({
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

module.exports = {
  sendAutomatedOrderEmail,
  sendScheduledOrderReminder,
  makePdf,
  configured
};
