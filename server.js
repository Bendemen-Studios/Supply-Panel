const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const envPath = path.join(__dirname, ".env");
require("dotenv").config({ path: envPath });

// Genereer en bewaar automatisch een sessiesleutel als .env ontbreekt
// of SESSION_SECRET niet minimaal 32 tekens bevat.
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  const generatedSecret = crypto.randomBytes(48).toString("hex");
  let envText = "";
  try { envText = fs.existsSync(envPath) ? fs.readFileSync(envPath, "utf8") : ""; } catch (_) {}
  const secretLine = "SESSION_SECRET=" + generatedSecret;
  if (/^SESSION_SECRET=.*$/m.test(envText)) {
    envText = envText.replace(/^SESSION_SECRET=.*$/m, secretLine);
  } else {
    envText = envText.replace(/\s*$/, "") + (envText.trim() ? "\n" : "") + secretLine + "\n";
  }
  fs.writeFileSync(envPath, envText, { mode: 0o600 });
  process.env.SESSION_SECRET = generatedSecret;
  console.warn("SESSION_SECRET ontbrak of was te kort; automatisch een veilige sleutel aangemaakt in .env.");
}
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const db = require("./src/db");
const { requireAuth, requireAdmin } = require("./src/auth");
const woo = require("./src/woocommerce");
const { sendAutomatedOrderEmail, sendScheduledOrderReminder, sendSecurityCodeEmail, verifySmtpConnection } = require("./src/order-mail");
const { addBillingPeriod } = require("./src/billing-period");
const { shiftDate, reminderSchedule } = require("./src/order-reminders");

const app = express();
const PORT = Number(process.env.SERVER_PORT || process.env.PORT || 3000);
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression({ threshold: 1024, level: 6 }));
app.use(express.urlencoded({ extended: false, limit: "2mb", verify: (req,res,buf) => { req.rawBody = Buffer.from(buf); } }));
app.use(express.json({ limit: "2mb", verify: (req,res,buf) => { req.rawBody = Buffer.from(buf); } }));
const PersistentSessionStore = require("./src/session-store");
const redis = require("./src/redis");
const sessionStore = new PersistentSessionStore();
app.use(session({
  store: sessionStore, name: "bendemen.sid", secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8 * 60 * 60 * 1000 }
}));

const orderImageDir = path.join(__dirname, "data", "order-images");
fs.mkdirSync(orderImageDir, { recursive: true });
const orderImageUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, orderImageDir),
    filename: (_req, file, cb) => {
      const ext = ({ "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp" })[file.mimetype];
      cb(null, Date.now() + "-" + crypto.randomBytes(10).toString("hex") + ext);
    }
  }),
  limits: { fileSize: 8 * 1024 * 1024, files: 10 },
  fileFilter: (_req, file, cb) => {
    if (!["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)) return cb(new Error("Gebruik een JPG-, PNG- of WEBP-afbeelding."));
    cb(null, true);
  }
});

app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "1h", etag: true, lastModified: true,
  setHeaders(res, filePath) {
    if (/\.(?:png|jpe?g|webp|svg|ico|woff2?)$/i.test(filePath)) res.setHeader("Cache-Control", "public, max-age=604800, stale-while-revalidate=86400");
    else res.setHeader("Cache-Control", "public, max-age=3600, stale-while-revalidate=300");
  }
}));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });
const securityCodeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
const euro = cents => new Intl.NumberFormat("nl-NL", { style: "currency", currency: "EUR" }).format((cents || 0) / 100);
const money = euro;
const supplyOrderNumber = value => "SUPPLY-" + String(value || "").padStart(3, "0");
function page(req, title, body) {
  const user = req.session.user;
  return `<!doctype html><html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} | Bendemen Supply Panel</title><link rel="icon" href="/favicon.ico" sizes="any"><link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png"><link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png"><link rel="stylesheet" href="/style.css"></head><body>
  <header class="top"><a class="brand" href="/"><img class="brand-logo" src="/Supply%20Panel%20Logo.png" alt="Bendemen Supply Panel"></a>${user ? `<nav><a href="/">Dashboard</a><a href="/orders">Bestellingen</a><a href="/services">Diensten</a>${user.role === "admin" ? '<details class="nav-dropdown"><summary>Beheer <span class="chevron">⌄</span></summary><div class="nav-dropdown-menu"><a href="/admin/customers">Klanten</a><a href="/admin/products">Producten</a><a href="/admin/subscriptions">Abonnementen</a><a href="/admin/orders">Orderoverzicht</a><a href="/admin/mail">Mail logs</a></div></details>' : ''}</nav><div class="account"><a class="profile-icon" href="/account" aria-label="Profiel" title="Profiel"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.5"></circle><path d="M4.5 20c.6-4 3.3-6 7.5-6s6.9 2 7.5 6"></path></svg></a><form method="post" action="/logout"><button class="linkbtn">Uitloggen</button></form></div>` : '<a class="mutedlink" href="/login">Inloggen</a>'}</header>
  <main class="wrap">${body}</main><footer>© ${new Date().getFullYear()} Bendemen <span>Bendemen Supply Panel</span></footer></body></html>`;
}
// Toon foutmeldingen uit routes als een duidelijke melding in de applicatie,
// in plaats van kale tekst op een verder lege pagina.
app.use((req,res,next)=>{
  const originalSend=res.send;
  res.send=function(body){
    if(res.statusCode>=400 && typeof body==="string" &&
       !/<(?:!doctype|html|body|main|section|div)\\b/i.test(body)){
      const message=esc(body.replace(/<[^>]*>/g," ").trim()||"Er is iets misgegaan.");
      body=page(req,"Melding",'<section class="auth-card" role="alert"><div class="eyebrow">VERZOEK NIET GELUKT</div><h1>Er ging iets mis.</h1><p class="sub">'+message+'</p><div class="row-actions"><button class="primary" type="button" onclick="history.back()">Terug</button><a class="secondary" href="/">Naar dashboard</a></div></section>');
      res.type("html");
    }
    return originalSend.call(this,body);
  };
  next();
});
function moneyInput(value) { return Math.round(Number(String(value).replace(",", ".")) * 100); }
function orderItems(orderId) { return db.prepare("SELECT product_id,product_name,quantity,unit_price_cents,meta_data FROM order_items WHERE order_id=?").all(orderId); }
function cleanProductMeta(raw) {
 let values=[];try{values=Array.isArray(raw)?raw:JSON.parse(raw||"[]");}catch(_){values=[];}
 return values.filter(item=>{
  if(!item||typeof item.key!=="string"||item.value===undefined)return false;
  const key=item.key.trim().toLowerCase();
  return !key.startsWith("_")&&!key.startsWith("rank_math")&&!key.startsWith("rank-math")&&!key.startsWith("rankmath");
 });
}
function discardOrderUploads(req) {
 for(const file of req.files||[])if(file&&file.path)fs.unlink(file.path,()=>{});
}
function orderFeeLines(orderId) { return db.prepare("SELECT id,name,amount_cents FROM order_fee_lines WHERE order_id=? ORDER BY id").all(orderId); }
function recalculateOrderTotal(orderId) {
 const products=db.prepare("SELECT COALESCE(SUM(quantity*unit_price_cents),0) total FROM order_items WHERE order_id=?").get(orderId).total;
 const fees=db.prepare("SELECT COALESCE(SUM(amount_cents),0) total FROM order_fee_lines WHERE order_id=?").get(orderId).total;
 const total=Number(products||0)+Number(fees||0);
 db.prepare("UPDATE orders SET total_cents=? WHERE id=?").run(total,orderId);
 return total;
}
function displayOrderStatus(o) {
  if (o.workflow_status === "cancelled" || o.wc_status === "cancelled") return "Geannuleerd";
  if (["processing","completed"].includes(o.wc_status)) return "In behandeling";
  return o.wc_status || o.status;
}
function orderCard(o) {
  const payment = o.payment_url && !["processing","completed","refunded","cancelled"].includes(o.wc_status) ? `<a class="textlink" href="/orders/${o.id}/pay">Betalen →</a>` : "";
  return `<div class="order-row"><div><strong>${esc(o.order_number)}</strong><small>WooCommerce: ${esc(o.wc_order_number||"Nog niet gekoppeld")}</small><small>${esc(o.date)}</small></div><div class="order-products">${esc(o.summary || "Geen orderregels")}</div><div><span class="status">${esc(displayOrderStatus(o))}</span></div><strong>${money(o.total_cents)}</strong><div class="row-actions"><a class="textlink" href="/orders/${o.id}">Bekijken →</a>${payment}</div></div>`;
}
function getOrders(userId, limit = 100) {
  return db.prepare(`SELECT o.*, printf('SUPPLY-%03d', COALESCE(o.local_order_no,o.id)) order_number,
    strftime('%d-%m-%Y',o.created_at) date,
    (SELECT group_concat(oi.quantity || '× ' || oi.product_name, ', ') FROM order_items oi WHERE oi.order_id=o.id) summary
    FROM orders o WHERE o.user_id=? AND (o.show_in_history=1 OR o.recurring_order_id IS NOT NULL) ORDER BY o.id DESC LIMIT ?`).all(userId, limit);
}
// Voorkom dat meerdere gelijktijdige triggers dezelfde lokale order tweemaal
// als nieuwe WooCommerce-order aanmaken wanneer wc_order_id nog niet is opgeslagen.
const wooOrderSyncInFlight=new Map();
function syncWooOrder(orderId){
  const key=Number(orderId);
  if(wooOrderSyncInFlight.has(key))return wooOrderSyncInFlight.get(key);
  const task=syncWooOrderInternal(key).finally(()=>wooOrderSyncInFlight.delete(key));
  wooOrderSyncInFlight.set(key,task);
  return task;
}
async function syncWooOrderInternal(orderId) {
  try {
    const order=db.prepare("SELECT o.*,u.wc_customer_id,u.email customer_email,u.name customer_name,u.billing_first_name,u.billing_last_name,u.billing_company,u.billing_address_1,u.billing_address_2,u.billing_postcode,u.billing_city,u.billing_state,u.billing_country,u.billing_phone FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?").get(orderId);
    if(!order)throw new Error("Lokale bestelling niet gevonden.");
    // Repair legacy order rows: older versions stored the local products.id as
    // WooCommerce product_id and did not copy the catalog product metadata.
    const legacyItems=db.prepare("SELECT id,product_id,product_name,meta_data FROM order_items WHERE order_id=?").all(orderId);
    const repair=db.prepare("UPDATE order_items SET product_id=?,meta_data=? WHERE id=?");
    for(const item of legacyItems){
      const storedId=String(item.product_id||"");
      // Nieuwe Supply Panel-orders bewaren een nog niet gekoppeld catalogusproduct
      // als local:<products.id>. Zet dit vóór WooCommerce-sync om naar het echte
      // WooCommerce-product-ID zodra dat beschikbaar is; anders wordt het product
      // onterecht als fee-regel aangemaakt en dubbel op de PDF getoond.
      const localMatch=storedId.match(/^local:(\d+)$/);
      const legacyMatch=storedId.match(/^(\d+)$/);
      const catalog=localMatch
        ? db.prepare("SELECT id,wc_product_id,meta_data FROM products WHERE id=?").get(Number(localMatch[1]))
        : legacyMatch
          ? db.prepare("SELECT id,wc_product_id,meta_data FROM products WHERE id=?").get(Number(legacyMatch[1]))
          : null;
      if(catalog&&catalog.wc_product_id){
        repair.run(String(catalog.wc_product_id),"[]",item.id);
      }
    }
    const items=db.prepare("SELECT * FROM order_items WHERE order_id=?").all(orderId);
    const fees=db.prepare("SELECT name,amount_cents FROM order_fee_lines WHERE order_id=?").all(orderId);
    const isUpdate=Boolean(order.wc_order_id);
    const result=isUpdate?await woo.updateWooOrder(order.wc_order_id,items,fees):await woo.createWooOrder(order,items,fees);
    if(result?.id){
      db.prepare("UPDATE orders SET wc_order_id=?,wc_order_number=?,wc_status=?,payment_url=? WHERE id=?").run(String(result.id),result.number!=null?String(result.number):null,result.status||"pending",result.payment_url||null,orderId);
      console.log(`WooCommerce order ${result.id} ${isUpdate?"bijgewerkt":"aangemaakt"} voor ${supplyOrderNumber(order.local_order_no||order.id)}`);
      try{
        await woo.getInvoicePdf(result.id);
        console.log(`WP Overnight-factuur beschikbaar voor WooCommerce order ${result.id}`);
      }catch(invoiceError){
        console.error(`Factuur genereren mislukt voor WooCommerce order ${result.id}:`,invoiceError.response?.data?.message||invoiceError.message);
      }
    }
    return result;
  } catch (err) { console.error(`WooCommerce order sync mislukt voor lokale order ${orderId}:`, err.message); return null; }
}
// Kies het laagste vrije SUPPLY-nummer. Bestaande nummers blijven altijd gekoppeld
// aan hun order; verwijderde nummers vallen automatisch vrij voor hergebruik.
function nextFreeSupplyOrderNo(){
 const used=db.prepare("SELECT local_order_no FROM orders WHERE local_order_no IS NOT NULL ORDER BY local_order_no").all();
 let candidate=1;
 for(const row of used){
  const number=Number(row.local_order_no);
  if(number===candidate)candidate++;
  else if(number>candidate)break;
 }
 return candidate;
}
function assignMissingSupplyOrderNumbers(){
 const missing=db.prepare("SELECT id FROM orders WHERE local_order_no IS NULL ORDER BY datetime(created_at),id").all();
 const assign=db.prepare("UPDATE orders SET local_order_no=? WHERE id=? AND local_order_no IS NULL");
 db.transaction(()=>{for(const row of missing)assign.run(nextFreeSupplyOrderNo(),row.id);})();
}
assignMissingSupplyOrderNumbers();
let orderCleanupRunning=false;
async function syncDeletedWooOrders(){
 if(orderCleanupRunning)return {busy:true,checked:0,updated:0,removed:0,failed:0};
 orderCleanupRunning=true;
 const stats={busy:false,checked:0,updated:0,removed:0,failed:0,created:0};
 try{
  // Probeer eerst alle lokale orders zonder WooCommerce-koppeling alsnog naar WooCommerce te sturen.
  const pending=db.prepare("SELECT id FROM orders WHERE wc_order_id IS NULL OR wc_order_id='' ORDER BY id").all();
  for(const row of pending){
   stats.checked++;
   const result=await syncWooOrder(row.id);
   if(result&&result.id)stats.created++;
   else stats.failed++;
  }
  // Behoud lokale orders zonder WooCommerce-koppeling als WooCommerce tijdelijk niet bereikbaar is. Dit zijn vaak orders
  // waarvan de achtergrond-sync nog loopt of tijdelijk is mislukt.
  const linked=db.prepare("SELECT id,wc_order_id FROM orders WHERE wc_order_id IS NOT NULL AND wc_order_id != '' ORDER BY id").all();
  for(const row of linked){
   stats.checked++;
   try{
    const wcOrder=await woo.getOrder(row.wc_order_id);
    const items=Array.isArray(wcOrder.line_items)?wcOrder.line_items:[];
    // WooCommerce kan bij een prijsupdate de lokale productomschrijving of
    // zichtbare configuratiemeta niet terugsturen. Bewaar die gegevens dan
    // vanuit de bestaande orderregel in plaats van ze leeg te synchroniseren.
    const localItems=db.prepare("SELECT id,product_id,product_name,meta_data FROM order_items WHERE order_id=? ORDER BY id").all(row.id);
    const usedLocalIds=new Set();
    const tx=db.transaction(()=>{
     db.prepare("UPDATE orders SET wc_order_number=?,wc_status=?,total_cents=?,currency=? WHERE id=? AND wc_order_id=?")
      .run(wcOrder.number!=null?String(wcOrder.number):row.wc_order_id,String(wcOrder.status||"pending"),Math.round(Number(wcOrder.total||0)*100),String(wcOrder.currency||"EUR"),row.id,row.wc_order_id);
     db.prepare("DELETE FROM order_items WHERE order_id=?").run(row.id);
     db.prepare("DELETE FROM order_fee_lines WHERE order_id=?").run(row.id);
     const insertFee=db.prepare("INSERT INTO order_fee_lines (order_id,name,amount_cents) VALUES (?,?,?)");
     for(const fee of (Array.isArray(wcOrder.fee_lines)?wcOrder.fee_lines:[])){
      const amount=Number(fee.total);
      insertFee.run(row.id,String(fee.name||"Extra kosten"),Number.isFinite(amount)?Math.round(amount*100):0);
     }
     const insert=db.prepare("INSERT INTO order_items (order_id,product_id,product_name,quantity,unit_price_cents,meta_data) VALUES (?,?,?,?,?,?)");
     for(const item of items){
      const quantity=Math.max(1,Math.trunc(Number(item.quantity)||1));
      const lineTotal=Number(item.total);
      const unitPriceCents=Number.isFinite(lineTotal)?Math.round(lineTotal*100/quantity):0;
      const localMatch=localItems.find(local=>!usedLocalIds.has(local.id)&&(
       (item.product_id&&local.product_id&&String(item.product_id)===String(local.product_id))||
       (!item.product_id&&String(item.name||"").trim()&&String(item.name).trim()===String(local.product_name||"").trim())
      ))||localItems.find(local=>!usedLocalIds.has(local.id));
      if(localMatch)usedLocalIds.add(localMatch.id);
      let remoteMeta=Array.isArray(item.meta_data)?item.meta_data:[];
      let localMeta=[];try{localMeta=localMatch?JSON.parse(localMatch.meta_data||"[]"):[];}catch(_){localMeta=[];}
      const metaData=[];
      const productName=String(item.name||"").trim()||String(localMatch?.product_name||"WooCommerce regel");
      insert.run(row.id,item.product_id?String(item.product_id):(localMatch?.product_id||null),productName,quantity,unitPriceCents,JSON.stringify(metaData));
     }
    });
    tx();stats.updated++;
   }catch(err){
    if(err.response&&err.response.status===404){db.prepare("DELETE FROM orders WHERE id=? AND wc_order_id=?").run(row.id,row.wc_order_id);stats.removed++;}
    else{stats.failed++;console.error("Order sync mislukt voor WooCommerce order "+row.wc_order_id+":",err.message);}
   }
  }
 }catch(err){stats.failed++;console.error("WooCommerce order cleanup:",err.message);}
 finally{orderCleanupRunning=false;}
 return stats;
}
async function sendOrderWebhook(orderId) {
  const url = process.env.ORDER_WEBHOOK_URL; if (!url) return;
  const o = db.prepare(`SELECT o.*,u.name customer_name,u.email customer_email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?`).get(orderId);
  const items = orderItems(orderId).map(i => ({ productName: i.product_name, quantity: i.quantity, unitPriceCents: i.unit_price_cents }));
  const payload = { event:"order.created", order:{id:o.id,orderNumber:supplyOrderNumber(o.local_order_no||o.id),customer:{id:o.user_id,name:o.customer_name,email:o.customer_email},items,totalCents:o.total_cents,currency:o.currency,status:o.status,createdAt:o.created_at} };
  try { const headers={"content-type":"application/json"}; if(process.env.ORDER_WEBHOOK_TOKEN) headers.authorization=`Bearer ${process.env.ORDER_WEBHOOK_TOKEN}`; const response=await fetch(url,{method:"POST",headers,body:JSON.stringify(payload),signal:AbortSignal.timeout(Math.max(5000,Math.min(120000,Number(process.env.ORDER_WEBHOOK_TIMEOUT_MS)||20000)))}); if(!response.ok) console.error(`Order webhook HTTP ${response.status}`); }
  catch(err){console.error("Order webhook failed:",err.message);}
}
function createOrder(userId, lines, sourceOrderId=null, notes="", recurringOrderId=null, feeLines=[]) {
  if(!Array.isArray(lines)||!lines.length) throw new Error("Deze bestelling bevat geen producten.");
  const fees=Array.isArray(feeLines)?feeLines:[];
  const total=lines.reduce((sum,x)=>sum+x.quantity*x.unit_price_cents,0)+fees.reduce((sum,x)=>sum+x.amount_cents,0);
  const tx=db.transaction(()=>{
    const nextNo=nextFreeSupplyOrderNo();
    const order=db.prepare("INSERT INTO orders (user_id,status,total_cents,source_order_id,notes,recurring_order_id,local_order_no,show_in_history) VALUES (?,'Nieuw',?,?,?,?,?,1)").run(userId,total,sourceOrderId,notes,recurringOrderId,nextNo);
    const insert=db.prepare("INSERT INTO order_items (order_id,product_id,product_name,quantity,unit_price_cents,meta_data) VALUES (?,?,?,?,?,?)");
    for(const x of lines) insert.run(order.lastInsertRowid,x.product_id||null,x.product_name,x.quantity,x.unit_price_cents,"[]");
    const insertFee=db.prepare("INSERT INTO order_fee_lines (order_id,name,amount_cents) VALUES (?,?,?)");
    for(const fee of fees) insertFee.run(order.lastInsertRowid,fee.name,fee.amount_cents);
    return Number(order.lastInsertRowid);
  });
  return tx();
}

const MAIL_TYPES = new Set(["new_order", "reminder_7", "reminder_3"]);
function mailTypeLabel(type) {
  return ({new_order:"Nieuwe bestelling",reminder_7:"Herinnering 7 dagen",reminder_3:"Herinnering 3 dagen"})[type] || type;
}
function mailSubject(type, order) {
  if(type==="new_order")return "Bendemen Studios – bestelling #"+(order.number||order.id);
  if(type==="reminder_7")return "Herinnering: je bestelling staat over 7 dagen gepland";
  return "Laatste herinnering: je bestelling staat over 3 dagen gepland";
}
function loadMailOrder(orderId) {
  const row=db.prepare("SELECT o.*,COALESCE(NULLIF(r.email_override,''),u.email) customer_email FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN recurring_orders r ON r.id=o.recurring_order_id WHERE o.id=?").get(orderId);
  if(!row)return null;
  const items=db.prepare("SELECT product_name name,quantity FROM order_items WHERE order_id=?").all(orderId);
  return {
    id:row.id,
    user_id:row.user_id,
    number:supplyOrderNumber(row.local_order_no||row.id),
    total:(Number(row.total_cents||0)/100).toFixed(2),
    currency:row.currency||"EUR",
    line_items:items,
    email:row.customer_email,
    wc_status:row.wc_status
  };
}
function testMailOrder() {
  return {id:"test",number:"TEST-001",total:"19.95",currency:"EUR",line_items:[{name:"Voorbeeldproduct",quantity:2}]};
}
async function sendLoggedMail({type,to,orderId=null,daysBefore=null,orderDate=null,isTest=false,parentLogId=null}) {
  if(!MAIL_TYPES.has(type))throw new Error("Onbekend e-mailtype.");
  const recipient=String(to||"").trim();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient))throw new Error("Vul een geldig e-mailadres in.");
  const order=isTest?testMailOrder():loadMailOrder(orderId);
  if(!order)throw new Error("De gekoppelde bestelling bestaat niet meer.");
  const effectiveDays=type==="reminder_7"?7:type==="reminder_3"?3:null;
  const scheduledDate=effectiveDays?(orderDate||shiftDate(businessDate(),effectiveDays)):null;
  const subject=mailSubject(type,order)+(isTest?" (test)":"");
  const inserted=db.prepare(
    "INSERT INTO mail_logs (email_type,order_id,recipient,subject,status,is_test,days_before,order_date,parent_log_id) VALUES (?,?,?,?,'sending',?,?,?,?)"
  ).run(type,isTest?null:orderId,recipient,subject,isTest?1:0,effectiveDays,scheduledDate,parentLogId);
  const logId=Number(inserted.lastInsertRowid);
  try {
    let result;
    if(type==="new_order") {
      result=await sendAutomatedOrderEmail({to:recipient,order,isTest});
    } else {
      result=await sendScheduledOrderReminder({to:recipient,order,daysBefore:effectiveDays,orderDate:scheduledDate,isTest});
    }
    const accepted=Array.isArray(result&&result.accepted)?result.accepted.map(String):[];
    const rejected=Array.isArray(result&&result.rejected)?result.rejected.map(String):[];
    const smtpResponse=String(result&&result.response||"Geen SMTP-respons ontvangen").slice(0,1000);
    const acceptedRecipient=accepted.some(address=>address.toLowerCase()===recipient.toLowerCase());
    const deliveredToSmtp=acceptedRecipient && !rejected.some(address=>address.toLowerCase()===recipient.toLowerCase());
    if(!deliveredToSmtp) {
      const rejection=rejected.length?"Ontvanger geweigerd door SMTP: "+rejected.join(", "):"SMTP heeft geen geaccepteerde ontvanger teruggegeven.";
      db.prepare("UPDATE mail_logs SET status='failed',smtp_response=?,error=? WHERE id=?").run(smtpResponse,rejection,logId);
      console.error("SMTP heeft ontvanger niet geaccepteerd ("+type+") naar "+recipient+":",smtpResponse,rejection);
      return {success:false,logId,error:rejection};
    }
    db.prepare("UPDATE mail_logs SET status='sent',sent_at=CURRENT_TIMESTAMP,message_id=?,smtp_response=?,error=NULL WHERE id=?")
      .run(result&&result.messageId?String(result.messageId).slice(0,500):null,smtpResponse,logId);
    console.log("SMTP heeft e-mail geaccepteerd:",JSON.stringify({type,recipient,messageId:result&&result.messageId||null,response:smtpResponse,accepted,rejected,envelope:result&&result.envelope||null}));
    return {success:true,logId};
  } catch(error) {
    db.prepare("UPDATE mail_logs SET status='failed',error=? WHERE id=?")
      .run(String(error.message||error).slice(0,1500),logId);
    console.error("E-mail verzending mislukt ("+type+") naar "+recipient+":",error.message);
    return {success:false,logId,error:String(error.message||error)};
  }
}
async function sendOrderCreatedEmail(orderId) {
  const order=loadMailOrder(orderId);
  if(!order)return {success:false,error:"Bestelling niet gevonden."};
  return sendLoggedMail({type:"new_order",to:order.email,orderId});
}

// Externe koppelingen mogen het aanmaken van een lokale bestelling niet blokkeren.
// WooCommerce, webhooks en e-mail worden na de directe redirect op de achtergrond verwerkt.
function queueOrderNotifications(orderId) {
  setImmediate(async () => {
    try { await sendOrderWebhook(orderId); } catch (err) {
      console.error("Order webhook mislukt voor order "+orderId+":", err.message);
    }
    try { await sendOrderCreatedEmail(orderId); } catch (err) {
      console.error("Order e-mail mislukt voor order "+orderId+":", err.message);
    }
  });
}
function queueOrderIntegrations(orderId) {
  setImmediate(async () => {
    try { await syncWooOrder(orderId); } catch (err) {
      console.error("WooCommerce achtergrond-sync mislukt voor order "+orderId+":", err.message);
    }
    queueOrderNotifications(orderId);
  });
}




 
// WooCommerce is alleen de externe orderadministratie voor Supply Panel-orders.
// Inkomende WooCommerce-webhooks mogen nooit zelfstandig lokale SUPPLY-orders aanmaken.
app.post("/webhooks/woocommerce", (req,res) => {
  const topic = req.get("x-wc-webhook-topic") || "";
  const isSetupPing = !topic && req.is("application/x-www-form-urlencoded") &&
    req.body && Object.keys(req.body).length === 1 &&
    /^\d+$/.test(String(req.body.webhook_id || ""));
  if (isSetupPing) {
    console.info("WooCommerce webhook setup-ping bevestigd.");
    return res.status(200).json({ received: true, ping: true });
  }
  console.info("Inkomende WooCommerce-webhook genegeerd; Supply-orders worden uitsluitend vanuit het Supply Panel aangemaakt.", { topic: topic || "unknown" });
  return res.status(200).json({ received: true, ignored: true, reason: "supply_orders_are_dashboard_only" });
});

app.get("/register",(req,res)=>res.redirect("/login"));
app.post("/register",(req,res)=>res.status(403).send("Accountregistratie is alleen mogelijk via beheer."));

app.get("/email-login", async (req,res,next) => {
  const loginMessage=(code)=>res.redirect(303,"/login?"+code+"=1");
  try {
    const token=String(req.query.token||"");
    const parts=token.split(".");
    if(parts.length!==2||!process.env.SESSION_SECRET) return loginMessage("link_invalid");
    const [encoded,signature]=parts;
    const expected=crypto.createHmac("sha256",process.env.SESSION_SECRET).update(encoded).digest("hex");
    const suppliedSignature=Buffer.from(signature,"utf8"),expectedSignature=Buffer.from(expected,"utf8");
    if(suppliedSignature.length!==expectedSignature.length||!crypto.timingSafeEqual(suppliedSignature,expectedSignature)) return loginMessage("link_invalid");
    const payload=JSON.parse(Buffer.from(encoded,"base64url").toString("utf8"));
    const now=Math.floor(Date.now()/1000);
    if(!Number.isInteger(payload.exp)||payload.exp<now) return loginMessage("link_expired");
    if(!payload.user_id||!payload.order_id||!payload.nonce||payload.exp>now+5*24*60*60+60) return loginMessage("link_invalid");
    const order=db.prepare("SELECT id,user_id FROM orders WHERE id=? AND user_id=?").get(Number(payload.order_id),Number(payload.user_id));
    const user=db.prepare("SELECT id,name,email,role,active FROM users WHERE id=?").get(Number(payload.user_id));
    if(!order||!user||Number(user.active)!==1||user.role!=="customer") return loginMessage("link_unavailable");
    const nonceHash=crypto.createHash("sha256").update(String(payload.nonce)).digest("hex");
    const inserted=db.prepare("INSERT OR IGNORE INTO email_sso_tokens (nonce_hash,user_id,order_id,expires_at) VALUES (?,?,?,?)")
      .run(nonceHash,user.id,order.id,payload.exp);
    if(!inserted.changes) return loginMessage("link_used");
    const consumed=db.prepare("UPDATE email_sso_tokens SET used_at=? WHERE nonce_hash=? AND used_at IS NULL AND (expires_at=0 OR expires_at>=?)")
      .run(Date.now(),nonceHash,now);
    if(!consumed.changes) return loginMessage("link_expired");
    req.session.regenerate(err=>{
      if(err) return next(err);
      req.session.user={id:user.id,name:user.name,email:user.email,role:user.role};
      req.session.save(saveErr=>{
        if(saveErr) return next(saveErr);
        res.redirect(303,"/orders/"+order.id);
      });
    });
  } catch(error) {
    if(error instanceof SyntaxError) return loginMessage("link_invalid");
    next(error);
  }
});
app.get("/login",(req,res)=>{
  if(req.session.user)return res.redirect("/");
  const linkMessage=req.query.link_expired?'<div class="alert">Deze bestellingslink is verlopen (5 dagen geldig). Log hieronder in met je account of vraag een nieuwe bestellingsmail aan.</div>':req.query.link_used?'<div class="alert">Deze bestellingslink is al gebruikt. Log hieronder in of vraag een nieuwe bestellingsmail aan.</div>':req.query.link_invalid?'<div class="alert">Deze bestellingslink is ongeldig. Log hieronder in of vraag een nieuwe bestellingsmail aan.</div>':req.query.link_unavailable?'<div class="alert">Deze bestelling of dit account is niet meer beschikbaar. Log hieronder in of neem contact op met support.</div>':"";
  const error=req.query.error?'<div class="alert">Inloggen is niet gelukt. Controleer je e-mailadres en wachtwoord.</div>':"";
  res.send(page(req,"Inloggen",`<section class="auth-card"><div class="eyebrow">BENDEMEN STUDIOS</div><h1>Welkom terug.</h1><p class="sub">Log in met je e-mailadres en wachtwoord om je account te beheren.</p>${req.query.disabled?'<div class="alert">Je Supply Panel-account is uitgeschakeld. Je WooCommerce-account op de webshop blijft gewoon werken.</div>':""}${linkMessage}${error}<form method="post" action="/login" class="stack"><label>E-mailadres<input name="email" type="email" autocomplete="username" required></label><label>Wachtwoord<input name="password" type="password" autocomplete="current-password" required></label><button class="primary">Inloggen <span>→</span></button></form></section>`));
});

function createEmail2FACode() {
 const code=String(crypto.randomInt(0,1000000)).padStart(6,"0");
 return {code,hash:crypto.createHash("sha256").update(code).digest("hex"),expires:Date.now()+600000};
}
function validEmail2FACode(input,hash,expires) {
 if(!hash||!expires||Number(expires)<Date.now())return false;
 const candidate=crypto.createHash("sha256").update(String(input||"")).digest(),expected=Buffer.from(String(hash),"hex");
 return expected.length===candidate.length&&crypto.timingSafeEqual(candidate,expected);
}
function authenticatedUser(req,user){req.session.user={id:user.id,name:user.name,email:user.email,role:user.role};}
async function sendEmail2FACode(user,purpose){
 const c=createEmail2FACode();
 db.prepare("UPDATE users SET email_2fa_code_hash=?,email_2fa_expires_at=? WHERE id=?").run(c.hash,c.expires,user.id);
 await sendSecurityCodeEmail({to:user.email,code:c.code,purpose});
}
app.post("/login",loginLimiter,async(req,res)=>{
 const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
 const user=db.prepare("SELECT * FROM users WHERE email=? COLLATE NOCASE").get(email);
 if(!user||user.active!==1||!["admin","customer"].includes(user.role)||(user.role==="customer"&&!user.wc_customer_id)||!(await bcrypt.compare(password,user.password_hash)))return res.redirect("/login?error=1");
 req.session.regenerate(async err=>{
  if(err)return res.status(500).send("Sessie kon niet worden gestart.");
  if(Number(user.email_2fa_enabled)===1){
   req.session.pendingEmail2FA={userId:user.id,expiresAt:Date.now()+600000,attempts:0};
   try{await sendEmail2FACode(user,"login");res.redirect("/login/2fa");}
   catch(error){console.error("Email 2FA login-code failed:",error.message);req.session.destroy(()=>res.redirect("/login?mail_error=1"));}
   return;
  }
  authenticatedUser(req,user);
  res.redirect(Number(user.email_2fa_prompt_snoozed_until||0)>Date.now()?(user.role==="admin"?"/admin":"/"):"/account/security/2fa?offer=1");
 });
});
app.get("/login/2fa",(req,res)=>{
 if(!req.session.pendingEmail2FA)return res.redirect("/login");
 res.send(page(req,"E-mailcode",'<section class="auth-card"><div class="eyebrow">EXTRA BEVEILIGING</div><h1>Controleer je e-mail.</h1><p class="sub">We hebben een zescijferige inlogcode gestuurd naar je accountadres.</p>'+(req.query.error?'<div class="alert">De code is onjuist of verlopen.</div>':'')+'<form method="post" action="/login/2fa" class="stack"><label>Beveiligingscode<input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required></label><button class="primary">Inloggen</button></form><form method="post" action="/login/2fa/resend" class="stack"><button class="secondary">Nieuwe code versturen</button></form></section>'));
});
app.post("/login/2fa",loginLimiter,(req,res)=>{
 const pending=req.session.pendingEmail2FA;
 if(!pending||pending.expiresAt<Date.now())return res.redirect("/login?error=1");
 const user=db.prepare("SELECT * FROM users WHERE id=? AND active=1 AND email_2fa_enabled=1").get(pending.userId);
 if(!user)return req.session.destroy(()=>res.redirect("/login"));
 if(!validEmail2FACode(req.body.code,user.email_2fa_code_hash,user.email_2fa_expires_at)){
  pending.attempts=(pending.attempts||0)+1;
  if(pending.attempts>=5)return req.session.destroy(()=>res.redirect("/login?error=1"));
  return res.redirect("/login/2fa?error=1");
 }
 db.prepare("UPDATE users SET email_2fa_code_hash=NULL,email_2fa_expires_at=NULL WHERE id=?").run(user.id);
 delete req.session.pendingEmail2FA;authenticatedUser(req,user);res.redirect(user.role==="admin"?"/admin":"/");
});
app.post("/login/2fa/resend",loginLimiter,async(req,res)=>{
 const pending=req.session.pendingEmail2FA;if(!pending||pending.expiresAt<Date.now())return res.redirect("/login");
 const user=db.prepare("SELECT * FROM users WHERE id=? AND active=1 AND email_2fa_enabled=1").get(pending.userId);
 if(!user)return res.redirect("/login");
 try{await sendEmail2FACode(user,"login");pending.expiresAt=Date.now()+600000;pending.attempts=0;res.redirect("/login/2fa");}
 catch(error){console.error("Email 2FA resend failed:",error.message);res.redirect("/login/2fa?error=1");}
});


app.get("/account/security/2fa",requireAuth,(req,res)=>{
 const user=db.prepare("SELECT * FROM users WHERE id=? AND active=1").get(req.session.user.id);if(!user)return res.status(404).send("Account niet gevonden.");
 const enabled=Number(user.email_2fa_enabled)===1,offer=req.query.offer==="1"&&!enabled;
 const notice=req.query.enabled?'<div class="success">E-mailverificatie is ingeschakeld.</div>':req.query.skipped?'<div class="success">We vragen je over 24 uur opnieuw.</div>':req.query.error?'<div class="alert">De code is onjuist of verlopen.</div>':"";
 const body='<div class="page-title"><div class="eyebrow">ACCOUNTBEVEILIGING</div><h1>E-mailverificatie</h1><p>Ontvang bij het inloggen een extra code per e-mail.</p></div><div class="panel"><h2>'+(enabled?'Ingeschakeld':'Niet ingeschakeld')+'</h2><p>'+(enabled?'Bij iedere login sturen we een code naar '+esc(user.email)+'.':'Deze extra beveiliging is optioneel.')+'</p>'+notice+(enabled?'<form method="post" action="/account/security/2fa/disable" class="stack"><label>Huidig wachtwoord<input name="password" type="password" autocomplete="current-password" required></label><button class="secondary">Uitschakelen</button></form>':offer?'<div class="row-actions"><form method="post" action="/account/security/2fa/skip"><button class="secondary">Overslaan (24 uur niet vragen)</button></form><form method="post" action="/account/security/2fa/setup"><button class="primary">E-mailverificatie instellen</button></form></div>':'<form method="post" action="/account/security/2fa/setup" class="stack"><button class="primary">E-mailverificatie inschakelen</button></form>')+'</div>';
 res.send(page(req,"E-mailverificatie",body));
});
app.post("/account/security/2fa/skip",requireAuth,(req,res)=>{
 db.prepare("UPDATE users SET email_2fa_prompt_snoozed_until=? WHERE id=?").run(Date.now()+86400000,req.session.user.id);res.redirect(req.session.user.role==="admin"?"/admin":"/");
});
app.post("/account/security/2fa/setup",requireAuth,securityCodeLimiter,async(req,res)=>{
 const user=db.prepare("SELECT * FROM users WHERE id=? AND active=1").get(req.session.user.id);if(!user)return res.status(404).send("Account niet gevonden.");
 try{await sendEmail2FACode(user,"setup");res.redirect("/account/security/2fa/verify?sent=1");}
 catch(error){console.error("Email 2FA setup failed:",error.message);res.status(502).send("De verificatiecode kon niet worden verstuurd. Controleer de e-mailinstellingen.");}
});
app.get("/account/security/2fa/verify",requireAuth,(req,res)=>{
 res.send(page(req,"Verificatiecode",'<section class="auth-card"><div class="eyebrow">ACCOUNTBEVEILIGING</div><h1>Bevestig je e-mailadres.</h1><p class="sub">Vul de zescijferige code in die we hebben gestuurd.</p>'+(req.query.sent?'<div class="success">Verificatiecode verstuurd.</div>':'')+(req.query.error?'<div class="alert">De code is onjuist of verlopen.</div>':'')+'<form method="post" action="/account/security/2fa/verify" class="stack"><label>Verificatiecode<input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required></label><button class="primary">Bevestigen en inschakelen</button></form><form method="post" action="/account/security/2fa/setup" class="stack"><button class="secondary">Nieuwe code versturen</button></form></section>'));
});
app.post("/account/security/2fa/verify",requireAuth,securityCodeLimiter,(req,res)=>{
 const user=db.prepare("SELECT * FROM users WHERE id=? AND active=1").get(req.session.user.id);if(!user)return res.status(404).send("Account niet gevonden.");
 if(!validEmail2FACode(req.body.code,user.email_2fa_code_hash,user.email_2fa_expires_at))return res.redirect("/account/security/2fa/verify?error=1");
 db.prepare("UPDATE users SET email_2fa_enabled=1,email_2fa_code_hash=NULL,email_2fa_expires_at=NULL,email_2fa_prompt_snoozed_until=NULL WHERE id=?").run(user.id);res.redirect("/account/security/2fa?enabled=1");
});
app.post("/account/security/2fa/disable",requireAuth,async(req,res)=>{
 const user=db.prepare("SELECT * FROM users WHERE id=? AND active=1").get(req.session.user.id);
 if(!user||!(await bcrypt.compare(String(req.body.password||""),user.password_hash)))return res.status(400).send("Het wachtwoord is onjuist.");
 db.prepare("UPDATE users SET email_2fa_enabled=0,email_2fa_code_hash=NULL,email_2fa_expires_at=NULL WHERE id=?").run(user.id);res.redirect("/account/security/2fa");
});
app.get("/account",requireAuth,(req,res)=>{
 const user=db.prepare("SELECT * FROM users WHERE id=? AND active=1").get(req.session.user.id);
 if(!user)return res.status(404).send("Account niet gevonden.");
 const saved=req.query.billing_saved?'<div class="success">Je factuuradres is opgeslagen'+(user.wc_customer_id?' en gesynchroniseerd met WooCommerce.':'.')+'</div>':'';
 const syncNotice=req.query.billing_synced?'<div class="success">De actuele factuurgegevens zijn opgehaald uit WooCommerce. De gegevens hieronder zijn bijgewerkt.</div>':req.query.billing_sync_error?'<div class="alert">Factuurgegevens synchroniseren is mislukt: '+esc(req.query.billing_sync_error)+'</div>':'';
 const billingForm='<div class="panel"><h2>Factuuradres</h2><p>Dit adres wordt gebruikt voor nieuwe bestellingen en facturen.</p>'+saved+syncNotice+'<form method="post" action="/account/billing" class="stack"><div class="form-grid"><label>Voornaam<input name="billing_first_name" value="'+esc(user.billing_first_name||"")+'" autocomplete="given-name" required></label><label>Achternaam<input name="billing_last_name" value="'+esc(user.billing_last_name||"")+'" autocomplete="family-name"></label></div><label>Bedrijfsnaam<input name="billing_company" value="'+esc(user.billing_company||"")+'" autocomplete="organization"></label><label>Straat en huisnummer<input name="billing_address_1" value="'+esc(user.billing_address_1||"")+'" autocomplete="address-line1" required></label><label>Toevoeging / tweede adresregel<input name="billing_address_2" value="'+esc(user.billing_address_2||"")+'" autocomplete="address-line2"></label><div class="form-grid"><label>Postcode<input name="billing_postcode" value="'+esc(user.billing_postcode||"")+'" autocomplete="postal-code" required></label><label>Plaats<input name="billing_city" value="'+esc(user.billing_city||"")+'" autocomplete="address-level2" required></label></div><div class="form-grid"><label>Provincie / regio<input name="billing_state" value="'+esc(user.billing_state||"")+'" autocomplete="address-level1"></label><label>Land<select name="billing_country" required><option value="NL"'+((user.billing_country||"NL")==="NL"?' selected':'')+'>Nederland</option><option value="BE"'+(user.billing_country==="BE"?' selected':'')+'>België</option><option value="DE"'+(user.billing_country==="DE"?' selected':'')+'>Duitsland</option><option value="GB"'+(user.billing_country==="GB"?' selected':'')+'>Verenigd Koninkrijk</option></select></label></div><label>Telefoon<input name="billing_phone" type="tel" value="'+esc(user.billing_phone||"")+'" autocomplete="tel"></label><button class="primary">Factuuradres opslaan</button></form>'+(user.wc_customer_id?'<form method="post" action="/account/billing/sync" style="margin-top:12px"><button class="secondary">Nu synchroniseren ↻</button><p class="hint">Haalt de nieuwste factuurgegevens rechtstreeks uit WooCommerce op.</p></form>':'<p class="hint">Dit account is niet gekoppeld aan een WooCommerce-klant.</p>')+'</div>';
 res.send(page(req,"Profiel",'<div class="page-title"><div class="eyebrow">ACCOUNT</div><h1>Profiel</h1><p>Je accountgegevens en beveiligingsinstellingen.</p></div><div class="panel profile-panel"><div><span class="profile-label">Naam</span><strong>'+esc(user.name)+'</strong></div><div><span class="profile-label">E-mailadres</span><strong>'+esc(user.email)+'</strong></div><div><span class="profile-label">Accounttype</span><strong>'+(user.role==="admin"?"Beheerder":"Klant")+'</strong></div><a class="primary inline" href="/account/password">Wachtwoord wijzigen <span>→</span></a><a class="secondary inline" href="/account/security/2fa">E-mailverificatie beheren →</a></div>'+billingForm));
});
app.post("/account/billing",requireAuth,async(req,res)=>{
 const user=db.prepare("SELECT id,wc_customer_id FROM users WHERE id=? AND active=1").get(req.session.user.id);
 if(!user)return res.status(404).send("Account niet gevonden.");
 const fields={billing_first_name:120,billing_last_name:120,billing_company:180,billing_address_1:200,billing_address_2:200,billing_postcode:30,billing_city:120,billing_state:120,billing_country:2,billing_phone:40};
 const values={};
 for(const [key,max] of Object.entries(fields))values[key]=String(req.body[key]||"").trim().slice(0,max);
 if(!values.billing_first_name||!values.billing_address_1||!values.billing_postcode||!values.billing_city||!["NL","BE","DE","GB"].includes(values.billing_country))return res.status(400).send("Vul minimaal voornaam, straat, postcode, plaats en een ondersteund land in.");
 const keys=Object.keys(fields);
 db.prepare("UPDATE users SET "+keys.map(key=>key+"=?").join(",")+" WHERE id=?").run(...keys.map(key=>values[key]),user.id);
 if(user.wc_customer_id){
  try{await woo.updateWooCustomerBilling(user.wc_customer_id,{first_name:values.billing_first_name,last_name:values.billing_last_name,company:values.billing_company,address_1:values.billing_address_1,address_2:values.billing_address_2,postcode:values.billing_postcode,city:values.billing_city,state:values.billing_state,country:values.billing_country,phone:values.billing_phone});}
  catch(err){console.error("WooCommerce billing address sync failed:",err.message);return res.status(502).send("Het factuuradres is lokaal opgeslagen, maar synchroniseren met WooCommerce is mislukt. Probeer opnieuw.");}
 }
 res.redirect("/account?billing_saved=1");
});
app.post("/account/billing/sync",requireAuth,async(req,res)=>{
 const user=db.prepare("SELECT id,wc_customer_id FROM users WHERE id=? AND active=1").get(req.session.user.id);
 if(!user)return res.status(404).send("Account niet gevonden.");
 if(!user.wc_customer_id)return res.status(400).send("Dit account is niet gekoppeld aan een WooCommerce-klant.");
 try{
  const customer=await woo.getCustomer(user.wc_customer_id);
  const billing=customer&&customer.billing?customer.billing:{};
  const value=(key,fallback="")=>String(billing[key]??fallback).trim();
  db.prepare(`UPDATE users SET
   billing_first_name=?,billing_last_name=?,billing_company=?,billing_address_1=?,
   billing_address_2=?,billing_postcode=?,billing_city=?,billing_state=?,
   billing_country=?,billing_phone=?
   WHERE id=? AND wc_customer_id=?`).run(
    value("first_name",customer.first_name||""),value("last_name",customer.last_name||""),
    value("company"),value("address_1"),value("address_2"),value("postcode"),
    value("city"),value("state"),value("country","NL").toUpperCase().slice(0,2),
    value("phone"),user.id,String(user.wc_customer_id)
   );
  res.redirect("/account?billing_synced=1");
 }catch(error){
  const message=String(error.response?.data?.message||error.message||"Onbekende fout").slice(0,250);
  console.error("Handmatige WooCommerce factuurgegevens-sync mislukt:",message);
  res.redirect("/account?billing_sync_error="+encodeURIComponent(message));
 }
});
app.get("/account/password",requireAuth,(req,res)=>{
 const body='<div class="page-title"><div class="eyebrow">ACCOUNT</div><h1>Wachtwoorden wijzigen</h1><p>De wachtwoorden van Supply Panel en WooCommerce beheer je afzonderlijk.</p>'+(req.query.updated?'<div class="alert">Je Supply Panel-wachtwoord is succesvol gewijzigd.</div>':'')+'</div><div class="panel"><h2>Supply Panel</h2><p>Wijzig alleen het wachtwoord waarmee je bij Supply Panel inlogt.</p><form method="post" action="/account/password" class="stack"><label>Huidig Supply Panel-wachtwoord<input name="current_password" type="password" autocomplete="current-password" required></label><label>Nieuw Supply Panel-wachtwoord<input name="new_password" type="password" minlength="6" maxlength="200" autocomplete="new-password" required></label><label>Herhaal nieuw wachtwoord<input name="confirm_password" type="password" minlength="6" maxlength="200" autocomplete="new-password" required></label><button class="primary">Supply Panel-wachtwoord wijzigen</button></form></div><div class="panel"><h2>WooCommerce</h2><p>Dit wachtwoord staat los van Supply Panel. Wijzig het via de beveiligde wachtwoordherstelpagina van de webshop.</p><a class="secondary inline" href="'+esc((process.env.WC_STORE_URL||"")+'/my-account/lost-password/')+'" target="_blank" rel="noopener">WooCommerce-wachtwoord wijzigen →</a></div>';
 res.send(page(req,"Wachtwoord wijzigen",body));
});
app.post("/account/password",requireAuth,async(req,res)=>{
 const user=db.prepare("SELECT * FROM users WHERE id=? AND active=1").get(req.session.user.id);
 const current=String(req.body.current_password||""),next=String(req.body.new_password||""),confirm=String(req.body.confirm_password||"");
 if(!user||!(await bcrypt.compare(current,user.password_hash)))return res.status(400).send("Het huidige wachtwoord is onjuist.");
 if(next.length<6||next.length>200||next!==confirm)return res.status(400).send("Het nieuwe wachtwoord moet minimaal 6 tekens bevatten en beide velden moeten overeenkomen.");
 try{
  const hash=await bcrypt.hash(next,12);
  db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash,user.id);
  res.redirect("/account/password?updated=1");
 }catch(err){console.error("Supply Panel password update failed:",err.message);res.status(502).send("Het Supply Panel-wachtwoord kon niet worden gewijzigd. Probeer het opnieuw.");
 }
});
app.post("/logout",requireAuth,(req,res)=>req.session.destroy(()=>res.redirect("/login")));

app.get("/",requireAuth,(req,res)=>{
  const user=req.session.user,orders=getOrders(user.id,5);
  const fixedCosts=db.prepare("SELECT COALESCE(SUM(ROUND(amount_cents * CASE interval WHEN 'week' THEN 52.0/12 WHEN 'year' THEN 1.0/12 ELSE 1 END)),0) total FROM monthly_costs WHERE user_id=? AND active=1").get(user.id).total;
  const subscriptionCosts=db.prepare("SELECT COALESCE(SUM(ROUND(amount_cents * CASE interval WHEN 'week' THEN 52.0/12 WHEN 'year' THEN 1.0/12 ELSE 1 END)),0) total FROM recurring_orders WHERE user_id=? AND status='active'").get(user.id).total;
  const monthly=fixedCosts+subscriptionCosts;
  const orderSpend=db.prepare("SELECT COALESCE(SUM(total_cents),0) total FROM orders WHERE user_id=? AND strftime('%Y-%m',created_at)=strftime('%Y-%m','now')").get(user.id).total;
  const body=`<div class="hero"><div><div class="eyebrow">BENDEMEN SUPPLY PANEL</div><h1>Goedendag, ${esc(user.name.split(" ")[0])}.</h1><p>Alles rondom jouw Inkoop Bestellingen op één plek.</p></div><a class="primary inline" href="/orders">Mijn bestellingen <span>→</span></a></div>
  <div class="stats"><article class="stat"><span>Vaste maandkosten</span><strong>${money(monthly)}</strong><small>Inclusief actieve abonnementen</small></article><article class="stat"><span>Besteld deze maand</span><strong>${money(orderSpend)}</strong><small>Nieuwe orders deze maand</small></article><article class="stat"><span>Totaal bestellingen</span><strong>${db.prepare("SELECT COUNT(*) n FROM orders WHERE user_id=?").get(user.id).n}</strong><small>Alle geregistreerde orders</small></article></div>
  <section class="section-head"><div><div class="eyebrow">RECENT</div><h2>Recente bestellingen</h2></div><a class="textlink" href="/orders">Alle bestellingen →</a></section><div class="panel">${orders.length?orders.map(orderCard).join(""):'<div class="empty">Je hebt nog geen bestellingen.</div>'}</div>
  <div class="bottom-cta"><div><strong>Hetzelfde product nog een keer nodig?</strong><p>Bestel opnieuw vanuit je bestelgeschiedenis.</p></div><a class="secondary" href="/orders">Bekijk historie</a></div>`;
  res.send(page(req,"Dashboard",body));
});
app.get("/orders",requireAuth,(req,res)=>{const orders=getOrders(req.session.user.id);res.send(page(req,"Bestellingen",`<div class="page-title"><div class="eyebrow">JOUW OVERZICHT</div><h1>Bestellingen</h1><p>Bekijk je eerdere inkoopbestellingen en bestel ze eenvoudig opnieuw.</p></div><div class="panel">${orders.length?orders.map(orderCard).join(""):'<div class="empty">Nog geen bestellingen gevonden.</div>'}</div>`));});
app.get("/orders/:id",requireAuth,async(req,res)=>{
  const id=Number(req.params.id),o=db.prepare("SELECT * FROM orders WHERE id=? AND user_id=?").get(id,req.session.user.id);
  if(!o)return res.status(404).send(page(req,"Niet gevonden","<h1>Bestelling niet gevonden</h1>"));
  try{await woo.refreshWooOrder(id);}catch(e){console.error("Woo status refresh:",e.message);}
  const fresh=db.prepare("SELECT * FROM orders WHERE id=?").get(id),items=orderItems(id);
  const rows=items.map(i=>{let meta=[];try{meta=JSON.parse(i.meta_data||"[]");}catch(_){meta=[];}const detail=meta.filter(m=>m&&typeof m.key==="string"&&!m.key.startsWith("_")).map(m=>`<small class="hint">${esc(m.key)}: ${esc(typeof m.value==="string"?m.value:JSON.stringify(m.value))}</small>`).join("");return `<tr><td><strong>${esc(i.product_name)}</strong>${detail}</td><td>${i.quantity}</td><td>${money(i.unit_price_cents)}</td><td>${money(i.quantity*i.unit_price_cents)}</td></tr>`;}).join("");
  const feeRows=orderFeeLines(id);
  const feeHtml=feeRows.map(f=>`<tr><td>${esc(f.name)}</td><td>—</td><td>—</td><td>${money(f.amount_cents)}</td></tr>`).join("");
  const payBlock=fresh.payment_url&&!["processing","completed","refunded","cancelled"].includes(fresh.wc_status)?`<div class="payment-box"><div><strong>Deze bestelling staat nog open</strong><p>Betaal veilig via de betaalpagina van Bendemen Studios.</p></div><a class="primary" href="/orders/${id}/pay">Nu betalen <span>→</span></a></div>`:(fresh.wc_status?`<p class="hint">WooCommerce-status: ${esc(displayOrderStatus(fresh))}</p>`:'<p class="hint">De WooCommerce-betaallink verschijnt zodra de winkelkoppeling is ingesteld.</p>');
  const exampleImages=db.prepare("SELECT id FROM order_example_images WHERE order_id=? ORDER BY id").all(id);
  const legacyImage=fresh.example_image_path?'<img src="/orders/'+id+'/example-image" alt="Productvoorbeeld" style="max-width:100%;max-height:420px;object-fit:contain;border-radius:10px">':"";
  const exampleImageBlock=(exampleImages.length||legacyImage)?'<div class="panel"><h2>Productvoorbeelden</h2><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px">'+legacyImage+exampleImages.map(img=>'<img src="/orders/'+id+'/example-images/'+img.id+'" alt="Productvoorbeeld" style="width:100%;max-height:320px;object-fit:contain;border-radius:10px">').join("")+'</div></div>':"";
  const invoiceBlock=fresh.wc_order_id&&["pending","on-hold","processing","completed","refunded"].includes(fresh.wc_status)?`<p class="invoice-action"><a class="secondary" href="/orders/${id}/pdf" target="_blank" rel="noopener">Factuur downloaden (PDF) →</a></p>`:"";
  res.send(page(req,"Bestelling",`<a class="back" href="/orders">← Terug naar bestellingen</a><div class="page-title"><div class="eyebrow">BESTELLING ${supplyOrderNumber(o.local_order_no||id)} · WOOCOMMERCE ${fresh.wc_order_number?esc(fresh.wc_order_number):"Nog niet gekoppeld"}</div><h1>Bestelling bekijken</h1><p>Aangemaakt op ${esc(o.created_at)} · <span class="status">${esc(displayOrderStatus(fresh))}</span></p></div>${payBlock}${invoiceBlock}${exampleImageBlock}${fresh.notes?`<div class="panel"><h2>Notities bij deze bestelling</h2><p style="white-space:pre-wrap">${esc(fresh.notes)}</p></div>`:""}<div class="panel"><div class="table-wrap"><table><thead><tr><th>Product</th><th>Aantal</th><th>Prijs per stuk</th><th>Totaal</th></tr></thead><tbody>${rows}${feeHtml}</tbody></table></div><div class="total-line"><span>Ordertotaal</span><strong>${money(o.total_cents)}</strong></div></div>${!fresh.recurring_order_id&&fresh.allow_reorder!==0?`<form method="post" action="/orders/${id}/reorder" class="reorder-form"><div><strong>Deze bestelling opnieuw bestellen?</strong><p>We maken een nieuwe order aan met dezelfde producten en aantallen.</p><label>Notitie bij herbestelling (optioneel)<textarea name="notes" rows="2" maxlength="2000" placeholder="Bijvoorbeeld: graag dezelfde uitvoering en verpakking"></textarea></label></div><button class="primary">Opnieuw bestellen <span>→</span></button></form>`:`<p class="hint">Dit is een maatwerkbestelling. Opnieuw bestellen is voor deze bestelling uitgeschakeld.</p>`}`));
});

app.get("/orders/:id/example-image",requireAuth,(req,res)=>{
  const id=Number(req.params.id);
  const order=db.prepare("SELECT user_id,example_image_path FROM orders WHERE id=?").get(id);
  if(!order|| (req.session.user.role!=="admin" && order.user_id!==req.session.user.id) || !order.example_image_path)
    return res.status(404).send("Productvoorbeeld niet gevonden.");
  const filename=path.basename(order.example_image_path);
  res.setHeader("Cache-Control","private, no-store");
  res.type(path.extname(filename).slice(1));
  res.sendFile(path.join(orderImageDir,filename),err=>{if(err&&!res.headersSent)res.status(404).end();});
});


app.get("/orders/:id/example-images/:imageId",requireAuth,(req,res)=>{
  const id=Number(req.params.id),imageId=Number(req.params.imageId);
  const order=db.prepare("SELECT user_id FROM orders WHERE id=?").get(id);
  const image=db.prepare("SELECT image_path FROM order_example_images WHERE id=? AND order_id=?").get(imageId,id);
  if(!order||!image||(req.session.user.role!=="admin"&&order.user_id!==req.session.user.id))return res.status(404).send("Productvoorbeeld niet gevonden.");
  const filename=path.basename(image.image_path);
  res.setHeader("Cache-Control","private, no-store");
  res.type(path.extname(filename).slice(1));
  res.sendFile(path.join(orderImageDir,filename),err=>{if(err&&!res.headersSent)res.status(404).end();});
});

app.get("/orders/:id/pay",requireAuth,(req,res)=>{
  const id=Number(req.params.id),order=db.prepare("SELECT o.id,o.payment_url,o.wc_status,o.workflow_status,o.wc_order_id,u.wc_customer_id FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=? AND o.user_id=?").get(id,req.session.user.id);
  if(!order)return res.status(404).send("Bestelling niet gevonden.");
  if(!order.payment_url||["processing","completed","refunded","cancelled"].includes(order.wc_status)||order.workflow_status==="cancelled")return res.status(409).send("Voor deze bestelling is geen betaling (meer) nodig.");
  const ssoUrl=String(process.env.WC_SSO_URL||"").trim().replace(/\/$/,"");
  const ssoSecret=String(process.env.WC_SSO_SECRET||"");
  if(ssoUrl&&ssoSecret.length>=32&&order.wc_order_id&&order.wc_customer_id&&/^\d+$/.test(String(order.wc_customer_id))){
    const claims={order_id:Number(order.wc_order_id),customer_id:Number(order.wc_customer_id),nonce:crypto.randomBytes(24).toString("hex"),exp:Math.floor(Date.now()/1000)+90};
    const encoded=Buffer.from(JSON.stringify(claims)).toString("base64url");
    const signature=crypto.createHmac("sha256",ssoSecret).update(encoded).digest("hex");
    return res.redirect(303,ssoUrl+"/wp-json/bendemen-sso/v1/login?token="+encodeURIComponent(encoded+"."+signature));
  }
  res.redirect(order.payment_url);
});
app.get("/orders/:id/pdf",requireAuth,async(req,res)=>{
  const id=Number(req.params.id),order=db.prepare("SELECT * FROM orders WHERE id=? AND user_id=?").get(id,req.session.user.id);
  if(!order||!order.wc_order_id)return res.status(404).send("WooCommerce-factuur niet gevonden.");
  if(!["pending","on-hold","processing","completed","refunded"].includes(order.wc_status))return res.status(409).send("Voor deze bestelling is nog geen factuur beschikbaar.");
  try{
    // Sync first so legacy product IDs/meta are repaired before WP Overnight renders the PDF.
    await syncWooOrder(id);
    const fresh=db.prepare("SELECT wc_order_id FROM orders WHERE id=? AND user_id=?").get(id,req.session.user.id);
    const pdf=await woo.getInvoicePdf(fresh?.wc_order_id||order.wc_order_id);
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition",`attachment; filename="${pdf.filename}"`);
    res.setHeader("Content-Length",pdf.length);
    res.send(pdf);
  }catch(err){
    console.error("Invoice Bridge PDF:",err.message);
    res.status(err.response?.status===404?404:502).send("De factuur is nog niet beschikbaar via Invoice Bridge. Controleer of WP Overnight de factuur in WooCommerce heeft aangemaakt.");
  }
});
app.get("/orders/:id/invoice",requireAuth,async(req,res)=>{
  const id=Number(req.params.id),order=db.prepare("SELECT * FROM orders WHERE id=? AND user_id=?").get(id,req.session.user.id);
  if(!order||!order.wc_order_id)return res.status(404).send("Factuur niet gevonden.");
  if(!["pending","on-hold","processing","completed","refunded"].includes(order.wc_status))return res.status(409).send("Voor deze bestelling is nog geen factuur beschikbaar.");
  try{
    const pdf=await woo.getInvoicePdf(order.wc_order_id);
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition",`inline; filename="${pdf.filename}"`);
    res.setHeader("Cache-Control","private, no-store");
    res.send(pdf);
  }catch(err){
    console.error("WP Overnight invoice retrieval failed:",err.message);
    res.status(err.response?.status===404?404:502).send("De WP Overnight-factuur is nog niet beschikbaar. Controleer of de factuur in WooCommerce is aangemaakt.");
  }
});
app.post("/orders/:id/reorder",requireAuth,async(req,res)=>{
  const id=Number(req.params.id),order=db.prepare("SELECT * FROM orders WHERE id=? AND user_id=?").get(id,req.session.user.id);
  if(!order)return res.status(404).send("Bestelling niet gevonden.");
  if(order.recurring_order_id)return res.status(403).send("Abonnementsbestellingen kunnen niet opnieuw besteld worden.");
  if(order.allow_reorder===0)return res.status(403).send("Opnieuw bestellen is voor deze bestelling uitgeschakeld.");
  const lines=orderItems(id).map(x=>({product_id:x.product_id,product_name:x.product_name,quantity:x.quantity,unit_price_cents:x.unit_price_cents,meta_data:x.meta_data||"[]"}));
  const fees=orderFeeLines(id).map(x=>({name:x.name,amount_cents:x.amount_cents}));
  const notes=String(req.body.notes||"").trim().slice(0,2000);
  try{const newId=createOrder(req.session.user.id,lines,id,notes||"Herbestelling",null,fees);queueOrderIntegrations(newId);res.redirect(`/orders/${newId}`);}catch(err){console.error(err);res.status(500).send("Herbestelling maken is mislukt.");}
});


app.get("/admin",requireAuth,requireAdmin,(req,res)=>res.redirect("/admin/customers"));
app.get("/admin/customers",requireAuth,requireAdmin,(req,res)=>{
 const showDisabled=req.query.show_disabled==="1";
 const customers=db.prepare("SELECT id,name,email,active,wc_customer_id FROM users WHERE role='customer' AND active=? ORDER BY name").all(showDisabled?0:1);
 const rows=customers.map(c=>'<tr><td>'+esc(c.name)+'</td><td>'+esc(c.email)+'</td><td>'+(c.wc_customer_id?'#'+esc(c.wc_customer_id):'Niet gekoppeld')+'</td><td>'+(c.active?'Actief':'Uitgeschakeld')+'</td><td><a href="/admin/customers/'+c.id+'">Bekijken</a> · <form method="post" action="/admin/customers/'+c.id+'/access" style="display:inline"><button class="secondary">'+(c.active?'Supply Panel uitschakelen':'Supply Panel activeren')+'</button></form></td></tr>').join("");
 res.send(page(req,"Klanten", (req.query.customer_deleted?'<div class="success">Supply Panel-toegang is uitgeschakeld. De klant is uit deze actieve klantenlijst verwijderd. Het WooCommerce-account blijft actief en bestellingen blijven bewaard.</div>':'')+'<div class="page-title"><div class="eyebrow">BEHEER</div><h1>Klanten</h1><p>Hier beheer je uitsluitend de toegang tot Supply Panel. Het WooCommerce-account op de webshop wordt niet uitgeschakeld of verwijderd.</p><div class="row-actions"><a class="primary inline" href="/admin/customers/search">Klant toevoegen →</a><a class="secondary" href="/admin/orders">Orderoverzicht →</a><a class="secondary" href="/admin/customers?show_disabled=1">Uitgeschakelde klanten</a></div></div><div class="panel"><table><thead><tr><th>Naam</th><th>E-mail</th><th>WooCommerce</th><th>Toegang</th><th>Actie</th></tr></thead><tbody>'+(rows||'<tr><td colspan="5">'+(showDisabled?'Geen uitgeschakelde klanten.':'Geen actieve klanten.')+'</td></tr>')+'</tbody></table></div>'));
});

app.get("/admin/mail",requireAuth,requireAdmin,(req,res)=>{
 const logs=db.prepare("SELECT * FROM mail_logs ORDER BY id DESC LIMIT 250").all();
 const rows=logs.map(log=>{
  const status=log.status==="sent"?"SMTP geaccepteerd":log.status==="failed"?"Mislukt":log.status==="skipped"?"Overgeslagen":"Bezig";
  const orderLabel=log.order_id?supplyOrderNumber(db.prepare("SELECT COALESCE(local_order_no,id) n FROM orders WHERE id=?").get(log.order_id)?.n||log.order_id):(log.is_test?"Testmail":"—");
  return '<tr><td>'+esc(log.created_at)+'</td><td>'+esc(mailTypeLabel(log.email_type))+(log.is_test?' <span class="mail-tag">TEST</span>':'')+'</td><td>'+esc(log.recipient)+'</td><td>'+esc(orderLabel)+'</td><td><span class="mail-status mail-'+esc(log.status)+'">'+esc(status)+'</span></td><td>'+esc(log.sent_at||'—')+'</td><td>'+(log.smtp_response?'<span title="'+esc(log.smtp_response)+'">SMTP: '+esc(log.smtp_response)+'</span><br>':'')+(log.error?'<span class="mail-error" title="'+esc(log.error)+'">'+esc(log.error)+'</span>':'—')+'</td><td><form method="post" action="/admin/mail/'+log.id+'/resend" onsubmit="return confirm(\'Deze e-mail opnieuw versturen naar '+esc(log.recipient)+'?\')"><button class="secondary">Opnieuw versturen</button></form></td></tr>';
 }).join("");
 const verifyNotice=req.query.smtp_ok?'<div class="success">SMTP-verbinding en authenticatie zijn gelukt. Dit controleert de verbinding, niet de aflevering in de inbox.</div>':req.query.smtp_error?'<div class="alert">SMTP-controle mislukt: '+esc(req.query.smtp_error)+'</div>':"";
 const notice=(req.query.sent||req.query.resent)?'<div class="success">De SMTP-server heeft de e-mail geaccepteerd. Dit bevestigt niet dat de e-mail in de inbox is afgeleverd.</div>':req.query.failed?'<div class="alert">Verzending mislukt. Bekijk de foutmelding in het logboek.</div>':"";
 const body='<a class="back" href="/admin">← Beheer</a><div class="page-title"><div class="eyebrow">BEHEER</div><h1>Mail logs</h1><p>Controleer of de SMTP-server berichten accepteert, test alle templates en verstuur een eerder bericht opnieuw. Een status SMTP geaccepteerd is geen afleverbevestiging voor de inbox.</p></div>'+notice+
 verifyNotice+'<div class="panel"><h2>SMTP-verbinding controleren</h2><p>Controleert of de server bereikbaar is en of de SMTP-inloggegevens worden geaccepteerd. Er wordt geen e-mail verstuurd.</p><form method="post" action="/admin/mail/verify"><button class="secondary">SMTP-verbinding testen</button></form></div>'+
 '<div class="panel"><h2>Testmail versturen</h2><p>De test wordt naar het ingevulde adres gestuurd en gebruikt voorbeeldgegevens. Er wordt geen echte bestelling aangemaakt.</p><form method="post" action="/admin/mail/test" class="stack"><label>Type e-mail<select name="email_type" required><option value="new_order">Nieuwe bestelling (voorbeeldmail)</option><option value="reminder_7">Herinnering 7 dagen</option><option value="reminder_3">Herinnering 3 dagen</option></select></label><label>Ontvanger<input name="to" type="email" value="'+esc(req.session.user.email||"")+'" required></label><button class="primary">Testmail versturen</button></form></div>'+
 '<div class="panel"><div class="section-head"><div><h2>Verzendgeschiedenis</h2><p class="hint">Laatste 250 verzendpogingen. SMTP geaccepteerd betekent dat de uitgaande mailserver het bericht aannam; de uiteindelijke aflevering in de inbox wordt hiermee niet bevestigd. Mislukte pogingen tonen de SMTP-fout.</p></div></div><div class="table-wrap"><table><thead><tr><th>Aangemaakt</th><th>Type</th><th>Ontvanger</th><th>Bestelling</th><th>Status</th><th>Verzonden</th><th>Foutmelding</th><th>Actie</th></tr></thead><tbody>'+(rows||'<tr><td colspan="8">Er zijn nog geen e-mails gelogd.</td></tr>')+'</tbody></table></div></div>';
 res.send(page(req,"Mail logs",body));
});
app.post("/admin/mail/verify",requireAuth,requireAdmin,async(req,res)=>{
 try {
  const result=await verifySmtpConnection();
  console.log("SMTP-verbinding gecontroleerd:",JSON.stringify(result));
  res.redirect("/admin/mail?smtp_ok=1");
 } catch(error) {
  const message=String(error.message||error).slice(0,500);
  console.error("SMTP-verbindingscontrole mislukt:",message);
  res.redirect("/admin/mail?smtp_error="+encodeURIComponent(message));
 }
});
app.post("/admin/mail/test",requireAuth,requireAdmin,async(req,res)=>{
 const type=String(req.body.email_type||"");
 const to=String(req.body.to||"").trim();
 if(!MAIL_TYPES.has(type))return res.status(400).send("Ongeldig e-mailtype.");
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to))return res.status(400).send("Vul een geldig e-mailadres in.");
 const result=await sendLoggedMail({type,to,isTest:true});
 res.redirect("/admin/mail?"+(result.success?"sent=1":"failed=1"));
});
app.post("/admin/mail/:id/resend",requireAuth,requireAdmin,async(req,res)=>{
 const logId=Number(req.params.id);
 const original=db.prepare("SELECT * FROM mail_logs WHERE id=?").get(logId);
 if(!original)return res.status(404).send("E-maillog niet gevonden.");
 if(!MAIL_TYPES.has(original.email_type))return res.status(400).send("Onbekend e-mailtype.");
 if(!original.is_test&&!original.order_id)return res.status(404).send("De oorspronkelijke bestelling is niet meer beschikbaar.");
 if(!original.is_test&&original.email_type!=="new_order") {
  const order=db.prepare("SELECT wc_order_id,wc_status,status FROM orders WHERE id=?").get(original.order_id);
  if(!order)return res.status(404).send("Bestelling niet gevonden.");
  const paid=new Set(["processing","completed","paid","betaald","refunded","cancelled","canceled"]);
  if(paid.has(String(order.wc_status||"").toLowerCase())||paid.has(String(order.status||"").toLowerCase()))
   return res.status(409).send("Deze herinnering kan niet opnieuw worden verstuurd: de bestelling is betaald of afgesloten.");
  if(order.wc_order_id) {
   try {
    const live=await woo.getOrder(order.wc_order_id);
    if(["processing","completed","refunded","cancelled"].includes(String(live.status||"").toLowerCase())||live.date_paid)
     return res.status(409).send("Deze herinnering kan niet opnieuw worden verstuurd: de WooCommerce-bestelling is betaald of afgesloten.");
   } catch(error) {
    console.error("WooCommerce statuscontrole vóór resend mislukt:",error.message);
    return res.status(503).send("De actuele betaalstatus kon niet worden gecontroleerd. Er is geen herinnering verstuurd.");
   }
  }
 }
 const result=await sendLoggedMail({
  type:original.email_type,
  to:original.recipient,
  orderId:original.order_id,
  daysBefore:original.days_before,
  orderDate:original.order_date,
  isTest:Boolean(original.is_test),
  parentLogId:original.id
 });
 res.redirect("/admin/mail?"+(result.success?"resent=1":"failed=1"));
});

app.post("/admin/orders/refresh",requireAuth,requireAdmin,async(req,res)=>{
 const stats=await syncDeletedWooOrders();
 if(stats.busy)return res.status(409).send("Er loopt al een WooCommerce-synchronisatie. Probeer het zo opnieuw.");
 res.redirect("/admin/orders?refresh_checked="+stats.checked+"&refresh_updated="+stats.updated+"&refresh_removed="+stats.removed+"&refresh_failed="+stats.failed+"&refresh_created="+(stats.created||0));
});
app.post("/admin/orders/:id/resend-email",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),to=String(req.body.to||"").trim();
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to))return res.status(400).send("Vul een geldig e-mailadres in.");
 const order=loadMailOrder(id);if(!order)return res.status(404).send("Bestelling niet gevonden.");
 const result=await sendLoggedMail({type:"new_order",to,orderId:id});
 res.redirect("/admin/orders?"+(result.success?"mail_resent=1":"mail_failed=1"));
});


app.get("/admin/orders/:id/pdf",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id);
 if(!Number.isSafeInteger(id)||id<1)return res.status(400).send("Ongeldig ordernummer.");
 const order=db.prepare("SELECT * FROM orders WHERE id=?").get(id);
 if(!order||!order.wc_order_id)return res.status(404).send("Geen gekoppelde WooCommerce-factuur gevonden.");
 if(!["pending","on-hold","processing","completed","refunded"].includes(order.wc_status))return res.status(409).send("Voor deze bestelling is nog geen factuur beschikbaar.");
 try{
  await syncWooOrder(id);
  const fresh=db.prepare("SELECT wc_order_id,local_order_no,id FROM orders WHERE id=?").get(id);
  const pdf=await woo.getInvoicePdf(fresh?.wc_order_id||order.wc_order_id);
  const filename=String(pdf.filename||("factuur-"+supplyOrderNumber(fresh.local_order_no||fresh.id)+".pdf")).replace(/[\\r\\n"\\/\\\\]/g,"_");
  res.setHeader("Content-Type","application/pdf");
  res.setHeader("Content-Disposition",'attachment; filename="'+filename+'"');
  res.setHeader("Cache-Control","private, no-store");
  res.setHeader("Content-Length",pdf.length);
  res.send(pdf);
 }catch(err){
  console.error("Admin Invoice Bridge PDF:",err.message);
  res.status(err.response?.status===404?404:502).send("De factuur is niet beschikbaar via Invoice Bridge. Controleer of WP Overnight de factuur in WooCommerce heeft aangemaakt.");
 }
});
app.post("/admin/orders/:id/invoice/refresh",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id);
 if(!Number.isSafeInteger(id)||id<1)return res.status(400).send("Ongeldig ordernummer.");
 const order=db.prepare("SELECT * FROM orders WHERE id=?").get(id);
 if(!order||!order.wc_order_id)return res.status(404).send("Geen gekoppelde WooCommerce-factuur gevonden.");
 if(!["pending","on-hold","processing","completed","refunded"].includes(order.wc_status))return res.status(409).send("Voor deze bestelling is nog geen factuur beschikbaar.");
 try{
  await syncWooOrder(id);
  const fresh=db.prepare("SELECT wc_order_id,local_order_no,id FROM orders WHERE id=?").get(id);
  const pdf=await woo.refreshInvoicePdf(fresh?.wc_order_id||order.wc_order_id);
  const filename=String(pdf.filename||("factuur-"+supplyOrderNumber(fresh.local_order_no||fresh.id)+".pdf")).replace(/[\\r\\n"\\/\\\\]/g,"_");
  res.setHeader("Content-Type","application/pdf");
  res.setHeader("Content-Disposition",'attachment; filename="'+filename+'"');
  res.setHeader("Cache-Control","private, no-store");
  res.setHeader("Content-Length",pdf.buffer.length);
  res.send(pdf.buffer);
 }catch(err){
  console.error("WP Overnight invoice refresh:",err.message);
  res.status(err.response?.status===404?404:502).send("Factuur regenereren via WP Overnight is mislukt: "+String(err.response?.data?.message||err.message).slice(0,300));
 }
});

app.get("/admin/orders/new",requireAuth,requireAdmin,(req,res)=>{
 const customers=db.prepare("SELECT id,name,email FROM users WHERE role='customer' AND active=1 ORDER BY name").all();
 const products=db.prepare("SELECT id,name,sku,price_cents FROM products WHERE active=1 ORDER BY name").all();
 const customerOptions=customers.map(c=>'<option value="'+c.id+'">'+esc(c.name)+' · '+esc(c.email)+'</option>').join("");
 const productRows=products.map(p=>'<tr><td><strong>'+esc(p.name)+'</strong>'+(p.sku?'<small>'+esc(p.sku)+'</small>':'')+'</td><td>'+money(p.price_cents)+'</td><td><button type="button" class="secondary add-to-cart" data-id="'+p.id+'" data-name="'+esc(p.name)+'" data-price="'+(p.price_cents/100).toFixed(2).replace(".",",")+'">＋ Toevoegen</button></td></tr>').join("");
 const body='<a class="back" href="/admin/orders">← Orderoverzicht</a><div class="page-title"><div class="eyebrow">BEHEER</div><h1>Supply order aanmaken</h1><p>Maak handmatig een nieuwe Supply-bestelling aan voor een klant. Het SUPPLY-ordernummer wordt automatisch toegewezen zodra je de bestelling aanmaakt; je hoeft dit niet zelf in te vullen.</p></div>'+
 (customers.length?'<form id="new-order-form" method="post" action="/admin/orders/new" enctype="multipart/form-data" class="stack"><div class="panel"><label>Klant<select name="user_id" required><option value="">Selecteer een klant</option>'+customerOptions+'</select></label></div><div class="panel"><h2>Productcatalogus</h2><p class="hint">Voeg producten één voor één toe aan het mandje. Daarna kun je per regel de prijs en het aantal aanpassen. Hetzelfde product kun je meerdere keren met verschillende prijzen toevoegen.</p><div class="table-wrap"><table><thead><tr><th>Product</th><th>Standaardprijs</th><th></th></tr></thead><tbody>'+productRows+'</tbody></table></div></div><div class="panel"><div class="section-head"><div><h2>Mandje</h2><p class="hint">Pas iedere regel afzonderlijk aan of verwijder deze uit het mandje.</p></div><strong id="cart-total">€ 0,00</strong></div><div class="table-wrap"><table><thead><tr><th>Product</th><th>Prijs per stuk (€)</th><th>Aantal</th><th>Regeltotaal</th><th></th></tr></thead><tbody id="cart-items"><tr id="cart-empty"><td colspan="5">Je mandje is nog leeg. Voeg hierboven producten toe.</td></tr></tbody></table></div></div><div class="panel"><h2>Extra bedragen / fee lines</h2><p class="hint">Voeg losse kosten toe die als aparte fee-regels op de WooCommerce-bestelling en factuur komen.</p><div id="fee-lines"></div><button type="button" class="secondary" id="add-fee">＋ Fee toevoegen</button></div><div class="panel"><h2>Foto’s bij de bestelling</h2><p class="hint">Maximaal 10 JPG-, PNG- of WEBP-foto’s (8 MB per foto).</p><input type="file" name="example_images" accept="image/jpeg,image/png,image/webp" multiple></div><div class="panel"><label>Opmerking voor op de factuur<textarea name="notes" rows="3" maxlength="2000" placeholder="Optionele factuuropmerking"></textarea></label><button class="primary" id="create-order-button" disabled>Supply order aanmaken</button></div></form><script>(function(){const form=document.getElementById("new-order-form"),body=document.getElementById("cart-items"),total=document.getElementById("cart-total"),submit=document.getElementById("create-order-button"),cart=[];const fees=document.getElementById("fee-lines");document.getElementById("add-fee").addEventListener("click",()=>{const row=document.createElement("div");row.className="row-actions";row.style.margin="10px 0";const name=document.createElement("input");name.name="fee_name";name.placeholder="Omschrijving, bijvoorbeeld verzendkosten";name.maxLength=120;name.required=true;const amount=document.createElement("input");amount.name="fee_amount";amount.placeholder="Bedrag (€)";amount.inputMode="decimal";amount.required=true;const remove=document.createElement("button");remove.type="button";remove.className="secondary";remove.textContent="Verwijderen";remove.addEventListener("click",()=>row.remove());row.append(name,amount,remove);fees.append(row);});const euro=n=>new Intl.NumberFormat("nl-NL",{style:"currency",currency:"EUR"}).format(n/100);const cents=v=>Math.round(Number(String(v).replace(",","."))*100);function render(){body.replaceChildren();let sum=0;if(!cart.length){const tr=document.createElement("tr"),td=document.createElement("td");td.colSpan=5;td.textContent="Je mandje is nog leeg. Voeg hierboven producten toe.";tr.append(td);body.append(tr);}cart.forEach((item,index)=>{const tr=document.createElement("tr");const name=document.createElement("td");name.textContent=item.name;const priceCell=document.createElement("td"),price=document.createElement("input");price.type="text";price.inputMode="decimal";price.value=item.price;price.setAttribute("aria-label","Prijs per stuk voor "+item.name);price.style.maxWidth="120px";price.addEventListener("change",()=>{const n=cents(price.value);if(!Number.isSafeInteger(n)||n<0||n>100000000){price.value=item.price;return;}item.price=price.value;render();});priceCell.append(price);const qtyCell=document.createElement("td"),qty=document.createElement("input");qty.type="number";qty.min="1";qty.max="999";qty.value=item.quantity;qty.style.maxWidth="80px";qty.addEventListener("change",()=>{const n=Number(qty.value);if(!Number.isInteger(n)||n<1||n>999){qty.value=item.quantity;return;}item.quantity=n;render();});qtyCell.append(qty);const lineTotal=document.createElement("td"),amount=cents(item.price)*item.quantity;sum+=amount;lineTotal.textContent=euro(amount);const action=document.createElement("td"),remove=document.createElement("button");remove.type="button";remove.className="secondary";remove.textContent="Verwijderen";remove.addEventListener("click",()=>{cart.splice(index,1);render();});action.append(remove);tr.append(name,priceCell,qtyCell,lineTotal,action);body.append(tr);});total.textContent=euro(sum);submit.disabled=!cart.length;}function syncHidden(){form.querySelectorAll("[data-cart-hidden]").forEach(x=>x.remove());cart.forEach((item,index)=>{for(const [name,value] of [["product_ids",item.id],["price_"+item.id+"_"+index,item.price],["quantity_"+item.id+"_"+index,item.quantity]]){const input=document.createElement("input");input.type="hidden";input.name=name;input.value=value;input.dataset.cartHidden="1";form.append(input);}});}document.querySelectorAll(".add-to-cart").forEach(button=>button.addEventListener("click",()=>{cart.push({id:button.dataset.id,name:button.dataset.name,price:button.dataset.price,quantity:1});render();syncHidden();}));const originalRender=render;render=function(){originalRender();syncHidden();};form.addEventListener("submit",event=>{syncHidden();if(!cart.length){event.preventDefault();alert("Voeg minimaal één product toe aan het mandje.");}});})();</script>':'<div class="panel"><p>Er zijn geen actieve klanten beschikbaar. Activeer of voeg eerst een klant toe.</p></div>');
 res.send(page(req,"Supply order aanmaken",body));
});
app.post("/admin/orders/new",requireAuth,requireAdmin,orderImageUpload.array("example_images",10),async(req,res)=>{
 const userId=Number(req.body.user_id),customer=db.prepare("SELECT id FROM users WHERE id=? AND role='customer' AND active=1").get(userId);
 if(!customer){discardOrderUploads(req);return res.status(400).send("Selecteer een geldige actieve klant.");}
 const raw=req.body.product_ids||[],ids=(Array.isArray(raw)?raw:[raw]).map(Number);
 if(!ids.length||ids.some(id=>!Number.isSafeInteger(id)||id<1)){discardOrderUploads(req);return res.status(400).send("Voeg minimaal één geldig product toe aan het mandje.");}
 const uniqueIds=[...new Set(ids)],placeholders=uniqueIds.map(()=>"?").join(",");
 const products=db.prepare("SELECT id,wc_product_id,name,meta_data FROM products WHERE active=1 AND id IN ("+placeholders+")").all(...uniqueIds);
 if(products.length!==uniqueIds.length){discardOrderUploads(req);return res.status(400).send("Een of meer geselecteerde producten zijn niet meer actief.");}
 const productMap=new Map(products.map(p=>[p.id,p])),lines=[];
 for(let index=0;index<ids.length;index++){
  const product=productMap.get(ids[index]),quantity=Number(req.body["quantity_"+ids[index]+"_"+index]||1),price=moneyInput(req.body["price_"+ids[index]+"_"+index]);
  if(!product){discardOrderUploads(req);return res.status(400).send("Een geselecteerd product is niet meer actief.");}
  if(!Number.isInteger(quantity)||quantity<1||quantity>999){discardOrderUploads(req);return res.status(400).send("Controleer de aantallen. Gebruik minimaal 1 en maximaal 999.");}
  if(!Number.isSafeInteger(price)||price<0||price>100000000){discardOrderUploads(req);return res.status(400).send("Controleer de productprijzen. Gebruik een bedrag tussen € 0,00 en € 1.000.000,00.");}
  lines.push({product_id:product.wc_product_id?String(product.wc_product_id):"local:"+String(product.id),product_name:product.name,quantity,unit_price_cents:price,meta_data:"[]"});
 }
 const feeNames=Array.isArray(req.body.fee_name)?req.body.fee_name:[req.body.fee_name].filter(Boolean);
 const feeAmounts=Array.isArray(req.body.fee_amount)?req.body.fee_amount:[req.body.fee_amount].filter(Boolean);
 const feeLines=[];
 for(let i=0;i<feeNames.length;i++){
  const name=String(feeNames[i]||"").trim().slice(0,120),amount=moneyInput(feeAmounts[i]||"");
  if(!name&&!feeAmounts[i])continue;
  if(!name||!Number.isSafeInteger(amount)||amount<0||amount>100000000){discardOrderUploads(req);return res.status(400).send("Controleer de omschrijving en het bedrag van iedere extra kostenregel.");}
  feeLines.push({name,amount_cents:amount});
 }
 const notes=String(req.body.notes||"").trim().slice(0,2000);
 try{
  const orderId=createOrder(userId,lines,null,notes,null,feeLines);
  for(const file of (req.files||[]))db.prepare("INSERT INTO order_example_images (order_id,image_path) VALUES (?,?)").run(orderId,file.filename);
  // Directe WooCommerce-sync vóór de redirect; de lokale order blijft zichtbaar, ook als Woo tijdelijk niet bereikbaar is.
  const wooResult=await syncWooOrder(orderId);
  queueOrderNotifications(orderId);
  const created=db.prepare("SELECT local_order_no FROM orders WHERE id=?").get(orderId);
  res.redirect("/admin/orders?order_created=1&woo_sync="+(wooResult&&wooResult.id?"ok":"failed")+"&order_number="+encodeURIComponent(supplyOrderNumber(created.local_order_no||orderId)));
 }catch(err){discardOrderUploads(req);console.error("Admin supply order creation failed:",err.message);res.status(500).send("Supply order aanmaken is mislukt.");}
});
app.get("/admin/orders",requireAuth,requireAdmin,(req,res)=>{
 const rows=db.prepare(`SELECT o.id,o.local_order_no,o.created_at,o.total_cents,o.status,o.wc_status,o.wc_order_id,o.wc_order_number,o.payment_url,u.name customer_name,u.email customer_email,COALESCE(NULLIF(r.email_override,''),u.email) mail_recipient,
 (SELECT group_concat(oi.quantity || '× ' || oi.product_name, ', ') FROM order_items oi WHERE oi.order_id=o.id) summary
 FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN recurring_orders r ON r.id=o.recurring_order_id ORDER BY o.id DESC LIMIT 500`).all();
 const body='<a class="back" href="/admin">← Beheer</a><div class="page-title"><div class="eyebrow">BEHEER</div><h1>Orderoverzicht</h1><p>Lokale bestellingen en hun WooCommerce-koppeling.</p><div class="row-actions"><a class="primary" href="/admin/orders/new">＋ Supply order aanmaken</a></div>'+(req.query.mail_resent?'<div class="success">Bestellingsmail opnieuw verzonden.</div>':req.query.mail_failed?'<div class="alert">Verzenden mislukt. Controleer de mail logs.</div>':'')+'<form method="post" action="/admin/orders/refresh" class="row-actions"><button class="primary">Nu synchroniseren ↻</button><span class="hint">Controleert verwijderde orders en haalt ordergegevens opnieuw op.</span></form>' + (req.query.order_created?'<div class="'+(req.query.woo_sync==="ok"?"success":"alert")+'">Bestelling '+esc(req.query.order_number||"")+' aangemaakt en '+(req.query.woo_sync==="ok"?"direct met WooCommerce gesynchroniseerd.":"lokaal opgeslagen. WooCommerce-sync is niet gelukt; de automatische synchronisatie probeert het opnieuw.")+'</div>':'') + (req.query.refresh_checked!==undefined ? '<div class="alert">Synchronisatie klaar: '+esc(req.query.refresh_checked)+' gecontroleerd, '+esc(req.query.created||req.query.refresh_created||0)+' nieuw aangemaakt in WooCommerce, '+esc(req.query.refresh_updated)+' bijgewerkt, '+esc(req.query.refresh_removed)+' verwijderd, '+esc(req.query.refresh_failed)+' fouten.</div>' : '') + '<div class="panel table-wrap"><table><thead><tr><th>Lokale order</th><th>Klant</th><th>Producten</th><th>Datum</th><th>Bedrag</th><th>WooCommerce ordernummer</th><th>WooCommerce status</th><th>Factuur</th><th>E-mail</th><th>Beheer</th></tr></thead><tbody>'+
 (rows.map(o=>'<tr><td><strong>SUPPLY-'+String(o.local_order_no||o.id)+'</strong></td><td>'+(String(o.customer_name||"").trim().toLowerCase()===String(o.customer_email||"").trim().toLowerCase()?'<strong>'+esc(o.customer_email)+'</strong>':'<strong>'+esc(o.customer_name)+'</strong><small>'+esc(o.customer_email)+'</small>')+'</td><td>'+esc(o.summary||'Geen orderregels')+'</td><td>'+esc(o.created_at)+'</td><td>'+money(o.total_cents)+'</td><td>'+esc(o.wc_order_number||"Nog niet gekoppeld")+'</td><td>'+esc(o.wc_status||'—')+'</td><td>'+(o.wc_order_id&&["pending","on-hold","processing","completed","refunded"].includes(o.wc_status)?'<div class="stack"><a class="secondary" href="/admin/orders/'+o.id+'/pdf">PDF downloaden ↓</a><form method="post" action="/admin/orders/'+o.id+'/invoice/refresh" onsubmit="return confirm(&quot;De WP Overnight-factuur opnieuw laten genereren en ophalen?&quot;)"><button class="secondary">Factuur regenereren ↻</button></form></div>':'<span class="hint">Nog niet beschikbaar</span>')+'</td><td><form method="post" action="/admin/orders/'+o.id+'/resend-email" class="stack" onsubmit="return confirm(&quot;Bestellingsmail opnieuw versturen?&quot;)"><input type="email" name="to" value="'+esc(o.mail_recipient)+'" required aria-label="Ontvanger e-mail" style="min-width:190px"><button class="secondary">Mail opnieuw sturen</button></form></td><td><a class="textlink" href="/admin/orders/'+o.id+'/products">Aanpassen →</a></td></tr>').join('')||'<tr><td colspan="9">Nog geen bestellingen.</td></tr>')+
 '</tbody></table></div><p class="hint">Toont de laatste 500 lokale bestellingen.</p>';
 res.send(page(req,"Orderoverzicht",body));
});
app.get("/admin/customers/search",requireAuth,requireAdmin,async(req,res)=>{
 const q=String(req.query.q||"").trim();let customers=[],error="";
 if(q.length>=2){try{customers=await woo.searchCustomers(q);}catch(err){console.error(err.message);error="WooCommerce-klanten konden niet worden opgehaald. Controleer de API-instellingen.";}}
 const rows=customers.map(c=>{
  const email=String(c.email||"").trim().toLowerCase(),name=[c.first_name,c.last_name].filter(Boolean).join(" ")||email;
  const existing=email?db.prepare("SELECT id,wc_customer_id FROM users WHERE email=? COLLATE NOCASE").get(email):null;
  return '<div class="order-row"><div><strong>'+esc(name)+'</strong><small>'+esc(email)+'</small></div><div>WooCommerce #'+esc(c.id)+'</div><div>'+(existing?(existing.wc_customer_id?'Al gekoppeld':'Supply-account bestaat'):'Nog geen Supply-account')+'</div><form method="post" action="/admin/customers/link" class="stack"><input type="hidden" name="wc_customer_id" value="'+esc(c.id)+'"><label>Startwachtwoord<input name="password" type="password" minlength="6" maxlength="200" required placeholder="Minimaal 6 tekens"></label><button class="primary">'+(existing?'Account koppelen / herstellen':'Toegang geven')+'</button></form></div>';
 }).join("");
 res.send(page(req,"Klant toevoegen",'<div class="page-title"><div class="eyebrow">WOOCOMMERCE</div><h1>Klant toevoegen</h1><p>Zoek een geregistreerde WooCommerce-klant op naam of e-mailadres.</p></div><div class="panel"><form method="get" action="/admin/customers/search" class="stack"><label>Naam of e-mailadres<input name="q" value="'+esc(q)+'" minlength="2" required placeholder="Naam of e-mailadres"></label><button class="primary">Zoeken in WooCommerce</button></form></div>'+(error?'<div class="alert">'+esc(error)+'</div>':'')+'<div class="panel">'+(q.length<2?'<div class="empty">Vul minimaal twee tekens in.</div>':rows||'<div class="empty">Geen WooCommerce-klanten gevonden.</div>')+'</div><a class="back" href="/admin">← Terug naar klanten</a>'));
});
app.post("/admin/customers/link",requireAuth,requireAdmin,async(req,res)=>{
 const wcId=String(req.body.wc_customer_id||"").trim(),password=String(req.body.password||"");
 if(!/^\d+$/.test(wcId)||password.length<6||password.length>200)return res.status(400).send("Ongeldig account of wachtwoord (minimaal 6 tekens).");
 try{
  const c=await woo.getCustomer(wcId),email=String(c.email||"").trim().toLowerCase(),name=[c.first_name,c.last_name].filter(Boolean).join(" ")||email;
  if(!email||email.indexOf("@")<1)return res.status(400).send("Deze WooCommerce-klant heeft geen geldig e-mailadres.");
  const hash=await bcrypt.hash(password,12),existing=db.prepare("SELECT id FROM users WHERE email=? COLLATE NOCASE").get(email);
  if(existing)db.prepare("UPDATE users SET name=?,password_hash=?,role='customer',active=1,wc_customer_id=? WHERE id=?").run(name,hash,wcId,existing.id);
  else db.prepare("INSERT INTO users (name,email,password_hash,role,active,wc_customer_id) VALUES (?,?,?,'customer',1,?)").run(name,email,hash,wcId);
  res.redirect("/admin");
 }catch(err){console.error("WooCommerce customer linking:",err.message);res.status(502).send("Klant koppelen is mislukt. Controleer de WooCommerce API en klantkoppeling.");}
});
app.post("/admin/customers/:id/delete",requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id);
 const customer=db.prepare("SELECT id FROM users WHERE id=? AND role='customer'").get(id);
 if(!customer)return res.status(404).send("Klant niet gevonden.");
 // Behoud lokale orders en WooCommerce-koppelingen: verwijder alleen accounttoegang.
 const result=db.prepare("UPDATE users SET active=0 WHERE id=? AND role='customer'").run(id);
 if(!result.changes)return res.status(404).send("Klant niet gevonden.");
 res.redirect("/admin?customer_deleted=1");
});
app.post("/admin/customers/:id/access",requireAuth,requireAdmin,(req,res)=>{
  const id=Number(req.params.id),customer=db.prepare("SELECT id FROM users WHERE id=? AND role='customer'").get(id);
  if(!customer)return res.status(404).send("Klant niet gevonden.");
  db.prepare("UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=? AND role='customer'").run(id);
  res.redirect("/admin");
});
app.get("/admin/customers/:id",requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id),customer=db.prepare("SELECT * FROM users WHERE id=? AND role='customer'").get(id);
 if(!customer)return res.status(404).send("Klant niet gevonden.");
 const q=String(req.query.q||"").trim().toLowerCase();
 const all=db.prepare(`SELECT o.*, printf('SUPPLY-%03d', COALESCE(o.local_order_no,o.id)) order_number,
 strftime('%d-%m-%Y',o.created_at) date,
 (SELECT group_concat(oi.quantity || '× ' || oi.product_name, ', ') FROM order_items oi WHERE oi.order_id=o.id) summary
 FROM orders o WHERE o.user_id=? ORDER BY o.id DESC`).all(id);
 const orders=q?all.filter(o=>[o.order_number,o.summary,o.notes,o.created_at].some(v=>String(v||"").toLowerCase().includes(q))):all;
 const rows=orders.map(o=>'<tr><td><input type="checkbox" name="order_ids" value="'+o.id+'" aria-label="Selecteer '+esc(o.order_number)+'"></td><td><strong>'+esc(o.order_number)+'</strong><small>'+esc(o.created_at)+'</small></td><td>'+esc(o.summary||"Geen orderregels")+'</td><td>'+money(o.total_cents)+'</td><td><a class="textlink" href="/admin/orders/'+o.id+'/products">Aanpassen</a></td></tr>').join("");
 const body='<a class="back" href="/admin">← Klanten</a><div class="page-title"><h1>'+esc(customer.name)+'</h1><p>'+esc(customer.email)+'</p></div><div class="panel"><h2>Orders zoeken en herbestellen</h2><form method="get" action="/admin/customers/'+id+'" class="row-actions"><input name="q" value="'+esc(req.query.q||"")+'" placeholder="Zoek SUPPLY-ordernummer of product"><button class="secondary">Zoeken</button><a class="textlink" href="/admin/customers/'+id+'">Wissen</a></form><form method="post" action="/admin/customers/'+id+'/reorder" class="stack"><div class="table-wrap"><table><thead><tr><th>Selecteer</th><th>Order</th><th>Producten</th><th>Bedrag</th><th>Actie</th></tr></thead><tbody>'+(rows||'<tr><td colspan="5">Geen orders gevonden.</td></tr>')+'</tbody></table></div><label>Notitie bij herbestelling<textarea name="notes" rows="3" maxlength="2000" placeholder="Bijvoorbeeld: klant wil dezelfde producten, maar levering op vrijdag"></textarea></label><button class="primary">Geselecteerde orders herbestellen</button></form></div>';
 res.send(page(req,"Klant",body));
});
app.post("/admin/customers/:id/reorder",requireAuth,requireAdmin,async(req,res)=>{
 const customerId=Number(req.params.id),customer=db.prepare("SELECT id FROM users WHERE id=? AND role='customer' AND active=1").get(customerId);
 if(!customer)return res.status(404).send("Klant niet gevonden.");
 const raw=req.body.order_ids||[],ids=[...new Set((Array.isArray(raw)?raw:[raw]).map(Number).filter(n=>Number.isSafeInteger(n)&&n>0))];
 if(!ids.length)return res.status(400).send("Selecteer minimaal één bestaande order.");
 const placeholders=ids.map(()=>"?").join(",");
 const selected=db.prepare("SELECT id FROM orders WHERE user_id=? AND id IN ("+placeholders+")").all(customerId,...ids);
 if(selected.length!==ids.length)return res.status(400).send("Een of meer geselecteerde orders horen niet bij deze klant.");
 const lines=ids.flatMap(id=>orderItems(id).map(x=>({product_id:x.product_id,product_name:x.product_name,quantity:x.quantity,unit_price_cents:x.unit_price_cents,meta_data:x.meta_data||"[]"})));
 if(!lines.length)return res.status(400).send("De geselecteerde orders bevatten geen orderregels.");
 const fees=ids.flatMap(id=>orderFeeLines(id).map(x=>({name:x.name,amount_cents:x.amount_cents})));
 const notes=String(req.body.notes||"").trim().slice(0,2000)||"Herbestelling op verzoek van beheer";
 try{const newId=createOrder(customerId,lines,null,notes,null,fees);queueOrderIntegrations(newId);res.redirect("/orders/"+newId);}
 catch(err){console.error("Admin customer reorder failed:",err.message);res.status(500).send("Herbestelling maken is mislukt.");}
});


app.get("/costs",requireAuth,(req,res)=>res.redirect("/services"));
app.get("/subscriptions",requireAuth,(req,res)=>res.redirect("/services"));
app.get("/services",requireAuth,(req,res)=>{
 const subs=db.prepare("SELECT * FROM recurring_orders WHERE user_id=? ORDER BY id DESC").all(req.session.user.id);
 const cards=subs.map(sub=>{const items=db.prepare("SELECT product_name,quantity,unit_price_cents FROM recurring_order_items WHERE recurring_order_id=?").all(sub.id);return '<div class="order-row"><div><strong>'+esc(sub.name)+'</strong><small>'+esc(sub.interval)+' · '+esc(sub.status)+'</small></div><div class="order-products">'+esc(items.map(x=>x.quantity+'× '+x.product_name).join(', ')||'Geen producten gekoppeld')+'</div><strong>'+money(sub.amount_cents)+'</strong><div>'+(sub.next_payment?'Volgende betaling: '+esc(sub.next_payment):'')+'</div></div>';}).join("");
 const serviceOrders=db.prepare("SELECT o.id,o.local_order_no,o.created_at,o.total_cents,o.wc_status,o.status,r.name service_name FROM orders o JOIN recurring_orders r ON r.id=o.recurring_order_id WHERE o.user_id=? ORDER BY o.id DESC LIMIT 100").all(req.session.user.id);
 const serviceOrderRows=serviceOrders.map(o=>'<tr><td><strong>'+esc(supplyOrderNumber(o.local_order_no||o.id))+'</strong><small>'+esc(o.created_at)+'</small></td><td>'+esc(o.service_name)+'</td><td>'+esc(displayOrderStatus(o))+'</td><td>'+money(o.total_cents)+'</td><td><a class="textlink" href="/orders/'+o.id+'">Bekijken →</a></td></tr>').join("");
 res.send(page(req,"Diensten",'<div class="page-title"><div class="eyebrow">JOUW OVERZICHT</div><h1>Diensten</h1><p>Bekijk je gekoppelde diensten en de bijbehorende orders.</p></div><div class="panel"><h2>Diensten & abonnementen</h2>'+(cards||'<div class="empty">Er zijn nog geen diensten aan je account gekoppeld.</div>')+'</div><div class="panel"><h2>Orders bij je diensten</h2><div class="table-wrap"><table><thead><tr><th>Order</th><th>Dienst</th><th>Status</th><th>Bedrag</th><th></th></tr></thead><tbody>'+(serviceOrderRows||'<tr><td colspan="5">Er zijn nog geen orders voor je diensten.</td></tr>')+'</tbody></table></div></div>'));
});
app.get("/admin/products",requireAuth,requireAdmin,(req,res)=>{
 const products=db.prepare("SELECT * FROM products ORDER BY active DESC,name").all();
 const rows=products.map(p=>'<tr><td>'+esc(p.name)+'</td><td>'+esc(p.sku||'—')+'</td><td>'+money(p.price_cents)+'</td><td>'+esc(p.source)+'</td><td>'+(p.wc_product_id?'Woo #'+esc(p.wc_product_id):'Handmatig')+'</td></tr>').join("");
 res.send(page(req,"Productbeheer",(req.query.sync!==undefined?'<div class="success">WooCommerce-producten bijgewerkt: '+esc(req.query.sync)+' producten opgehaald.</div>':'')+'<div class="page-title"><div class="eyebrow">BEHEER</div><h1>Producten</h1><p>Importeer WooCommerce-producten of voeg ze handmatig toe.</p></div><div class="panel"><h2>WooCommerce synchroniseren</h2><form method="post" action="/admin/products/sync"><button class="primary">Producten ophalen uit WooCommerce</button></form></div><div class="panel"><h2>Handmatig product toevoegen</h2><form method="post" action="/admin/products" class="stack"><label>Productnaam<input name="name" maxlength="180" required></label><label>SKU<input name="sku" maxlength="100"></label><label>Verkoopprijs in euro<input name="price" inputmode="decimal" placeholder="0,00" required></label><label>Product-URL<input name="product_url" type="url"></label><button class="primary">Product opslaan</button></form></div><div class="panel"><h2>Productcatalogus</h2><div class="table-wrap"><table><thead><tr><th>Product</th><th>SKU</th><th>Verkoopprijs</th><th>Bron</th><th>Koppeling</th></tr></thead><tbody>'+(rows||'<tr><td colspan="5">Nog geen producten. Synchroniseer WooCommerce of voeg handmatig toe.</td></tr>')+'</tbody></table></div></div>'));
});
app.post("/admin/products",requireAuth,requireAdmin,(req,res)=>{
 const name=String(req.body.name||"").trim(),sku=String(req.body.sku||"").trim(),price=moneyInput(req.body.price),cost=moneyInput(req.body.cost||"0"),url=String(req.body.product_url||"").trim();
 if(!name||!Number.isSafeInteger(price)||price<0||!Number.isSafeInteger(cost)||cost<0||url&&!/^https?:\/\//i.test(url))return res.status(400).send("Ongeldig product, verkoopprijs of inkoopkosten.");
 db.prepare("INSERT INTO products (name,sku,price_cents,product_url,source) VALUES (?,?,?,?,'manual')").run(name,sku||null,price,url||null);res.redirect("/admin/products");
});
app.post("/admin/products/sync",requireAuth,requireAdmin,async(req,res)=>{
 try{
  let pageNo=1,count=0;
  while(true){const list=await woo.listProducts(pageNo,100);if(!list.length)break;
   const upsert=db.prepare("INSERT INTO products (wc_product_id,name,sku,description,price_cents,product_url,image_url,meta_data,source,active,updated_at) VALUES (?,?,?,?,?,?,?,?,'woocommerce',1,CURRENT_TIMESTAMP) ON CONFLICT(wc_product_id) DO UPDATE SET name=excluded.name,sku=excluded.sku,description=excluded.description,price_cents=excluded.price_cents,product_url=excluded.product_url,image_url=excluded.image_url,meta_data=excluded.meta_data,active=1,updated_at=CURRENT_TIMESTAMP");
   const tx=db.transaction(items=>{for(const p of items){const cents=Math.round(Number(p.price||0)*100);upsert.run(String(p.id),p.name||'Product',p.sku||null,p.description||null,cents,p.permalink||null,p.images&&p.images[0]?p.images[0].src:null,JSON.stringify(cleanProductMeta(p.meta_data)));}});
   tx(list);count+=list.length;if(list.length<100)break;pageNo++;
  }
  res.redirect("/admin/products?sync="+count);
 }catch(err){console.error("WooCommerce product sync:",err.message);res.status(502).send("WooCommerce synchroniseren is mislukt. Controleer WC_STORE_URL, WC_CONSUMER_KEY en WC_CONSUMER_SECRET in .env.");}
});
app.post("/admin/orders/:id/products/sync",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id);
 if(!Number.isSafeInteger(id)||id<1||!db.prepare("SELECT id FROM orders WHERE id=?").get(id))return res.status(404).send("Bestelling niet gevonden.");
 try{
  let pageNo=1,count=0;
  const upsert=db.prepare("INSERT INTO products (wc_product_id,name,sku,description,price_cents,product_url,image_url,meta_data,source,active,updated_at) VALUES (?,?,?,?,?,?,?,?,'woocommerce',1,CURRENT_TIMESTAMP) ON CONFLICT(wc_product_id) DO UPDATE SET name=excluded.name,sku=excluded.sku,description=excluded.description,price_cents=excluded.price_cents,product_url=excluded.product_url,image_url=excluded.image_url,meta_data=excluded.meta_data,active=1,updated_at=CURRENT_TIMESTAMP");
  while(true){
   const list=await woo.listProducts(pageNo,100);
   if(!Array.isArray(list))throw new Error("WooCommerce gaf geen geldige productlijst terug.");
   const tx=db.transaction(rows=>{for(const p of rows){if(!p||!p.id)continue;const cents=Math.round(Number(p.price||0)*100);upsert.run(String(p.id),p.name||"Product",p.sku||null,p.description||null,Number.isFinite(cents)?cents:0,p.permalink||null,p.images&&p.images[0]?p.images[0].src:null,JSON.stringify(Array.isArray(p.meta_data)?p.meta_data:[]));}});
   tx(list);count+=list.length;if(list.length<100)break;if(++pageNo>100)throw new Error("Meer dan 10.000 producten; import afgebroken.");
  }
  res.redirect("/admin/orders/"+id+"/products?catalog_synced="+count);
 }catch(error){
  console.error("Handmatige catalogus-sync:",error.response?.data||error.message);
  res.redirect("/admin/orders/"+id+"/products?catalog_error="+encodeURIComponent(String(error.response?.data?.message||error.message).slice(0,180)));
 }
});
app.get("/admin/orders/:id/products",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),order=db.prepare("SELECT o.*,u.name customer_name FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?").get(id);if(!order)return res.status(404).send("Bestelling niet gevonden.");
 // Vernieuw de catalogus bij openen van het mandje. Zo zijn ook bestaande
 // lokale records die in WooCommerce gewijzigd zijn weer actueel.
 let products=[],catalogError="";
 try{
  let pageNo=1,remoteCount=0;
  const upsert=db.prepare("INSERT INTO products (wc_product_id,name,sku,description,price_cents,product_url,image_url,meta_data,source,active,updated_at) VALUES (?,?,?,?,?,?,?,?,'woocommerce',1,CURRENT_TIMESTAMP) ON CONFLICT(wc_product_id) DO UPDATE SET name=excluded.name,sku=excluded.sku,description=excluded.description,price_cents=excluded.price_cents,product_url=excluded.product_url,image_url=excluded.image_url,meta_data=excluded.meta_data,active=1,updated_at=CURRENT_TIMESTAMP");
  while(true){
   const remote=await woo.listProducts(pageNo,100);
   if(!Array.isArray(remote))throw new Error("WooCommerce API gaf geen productlijst terug.");
   const tx=db.transaction(rows=>{for(const p of rows){if(!p||!p.id)continue;const cents=Math.round(Number(p.price||0)*100);upsert.run(String(p.id),p.name||"Product",p.sku||null,p.description||null,Number.isFinite(cents)?cents:0,p.permalink||null,p.images&&p.images[0]?p.images[0].src:null,JSON.stringify(Array.isArray(p.meta_data)?p.meta_data:[]));}});
   tx(remote);remoteCount+=remote.length;
   if(remote.length<100)break;
   pageNo++;
   if(pageNo>100)throw new Error("Productimport afgebroken: meer dan 10.000 producten.");
  }
  products=db.prepare("SELECT id,name,price_cents FROM products WHERE active=1 ORDER BY name").all();
  if(!products.length)catalogError="WooCommerce heeft geen producten teruggegeven. Controleer of de producten gepubliceerd zijn en of de API-sleutels leesrechten hebben.";
 }catch(error){
  catalogError="Producten ophalen uit WooCommerce mislukt: "+String(error.response?.data?.message||error.message).slice(0,240);
  console.error("WooCommerce catalogus vernieuwen bij orderbewerking:",error.response?.data||error.message);
  products=db.prepare("SELECT id,name,price_cents FROM products WHERE active=1 ORDER BY name").all();
 }
 const items=db.prepare("SELECT * FROM order_items WHERE order_id=?").all(id);
 const options=products.map(p=>'<option value="'+p.id+'" data-price="'+(p.price_cents/100).toFixed(2)+'">'+esc(p.name)+' — '+money(p.price_cents)+'</option>').join("");
 const lines=items.map(x=>{let meta=[];try{meta=Array.isArray(x.meta_data)?x.meta_data:JSON.parse(x.meta_data||"[]");}catch(_){meta=[];}const visibleMeta=meta.filter(m=>m&&typeof m.key==="string"&&!m.key.startsWith("_")).map(m=>'<div class="hint">'+esc(m.key)+': '+esc(typeof m.value==="string"?m.value:JSON.stringify(m.value))+'</div>').join("");return '<tr><td><form method="post" action="/admin/orders/'+id+'/items/'+x.id+'/edit" class="stack"><label>Productnaam / omschrijving<input name="name" maxlength="180" value="'+esc(x.product_name)+'" required></label><label>Aantal<input name="quantity" type="number" min="1" max="999" value="'+x.quantity+'" required></label><label>Prijs per stuk (€)<input name="price" inputmode="decimal" value="'+(x.unit_price_cents/100).toFixed(2).replace(".",",")+'" required></label><div class="hint">Productmeta: standaard leeg.</div><button class="primary">Regel opslaan en synchroniseren</button></form></td><td>'+money(x.quantity*x.unit_price_cents)+'</td><td><form method="post" action="/admin/orders/'+id+'/items/'+x.id+'/delete" onsubmit="return confirm(&quot;Deze orderregel verwijderen?&quot;)"><button class="danger">Verwijderen</button></form></td></tr>';}).join("");
 const exampleImages=db.prepare("SELECT id FROM order_example_images WHERE order_id=? ORDER BY id").all(id);
 const feeLines=orderFeeLines(id);
 const feeRows=feeLines.map(f=>'<tr><td><form method="post" action="/admin/orders/'+id+'/fees/'+f.id+'/edit" class="row-actions"><input name="name" maxlength="120" value="'+esc(f.name)+'" required><input name="amount" inputmode="decimal" value="'+(f.amount_cents/100).toFixed(2).replace(".",",")+'" required><button class="secondary">Opslaan</button></form></td><td><form method="post" action="/admin/orders/'+id+'/fees/'+f.id+'/delete"><button class="danger">Verwijderen</button></form></td></tr>').join("");
 const feePanel='<div class="panel"><h2>Aparte bedragen / fee lines</h2><p>Deze bedragen worden als aparte kostenregels naar WooCommerce gestuurd.</p><table><thead><tr><th>Omschrijving en bedrag (€)</th><th></th></tr></thead><tbody>'+(feeRows||'<tr><td colspan="2">Nog geen aparte bedragen.</td></tr>')+'</tbody></table></div>';
 const settingsPanel='<div class="panel"><h2>Herbestellen en productvoorbeelden</h2><form method="post" action="/admin/orders/'+id+'/settings" enctype="multipart/form-data" class="stack"><label style="display:flex;align-items:center;gap:10px"><input type="checkbox" name="allow_reorder" value="1" '+(order.allow_reorder!==0?'checked':'')+' style="width:auto"> Deze bestelling is herbestelbaar</label><label>Productfoto’s toevoegen (max. 10 foto’s per keer, JPG, PNG of WEBP, max. 8 MB per foto)<input type="file" name="example_images" accept="image/jpeg,image/png,image/webp" multiple></label>'+(order.example_image_path?'<div><img src="/orders/'+id+'/example-image" alt="Oud productvoorbeeld" style="display:block;max-width:180px;max-height:140px;object-fit:contain;border-radius:8px;margin:8px 0">Oude voorbeeldfoto</div>':'')+exampleImages.map(img=>'<label style="display:flex;align-items:center;gap:10px"><img src="/orders/'+id+'/example-images/'+img.id+'" alt="Productvoorbeeld" style="width:90px;height:70px;object-fit:contain;border-radius:8px"><input type="checkbox" name="remove_image_ids" value="'+img.id+'" style="width:auto"> Deze foto verwijderen</label>').join("")+'<button class="primary">Instellingen opslaan</button></form></div>';
 res.send(page(req,supplyOrderNumber(order.local_order_no||id)+" bewerken",(catalogError?'<div class="alert">'+esc(catalogError)+'</div>':'')+(req.query.catalog_synced!==undefined?'<div class="success">WooCommerce-productimport afgerond: '+esc(req.query.catalog_synced)+' producten opgehaald.</div>':'')+(req.query.catalog_error?'<div class="alert">WooCommerce-import mislukt: '+esc(req.query.catalog_error)+'</div>':'')+settingsPanel+(req.query.settings_saved?'<div class="success">Herbestelinstelling en productvoorbeeld opgeslagen.</div>':req.query.settings_error?'<div class="alert">Instellingen konden niet volledig worden opgeslagen.</div>':"")+(req.query.sync_failed?'<div class="alert">Lokaal opgeslagen, maar synchroniseren met WooCommerce is mislukt. Probeer opnieuw.</div>':req.query.item_saved?'<div class="success">Orderregel opgeslagen en gesynchroniseerd.</div>':req.query.item_deleted?'<div class="success">Orderregel verwijderd en gesynchroniseerd.</div>':'')+'<a class="back" href="/admin">← Beheer</a><div class="page-title"><h1>Producten koppelen aan SUPPLY-'+String(order.local_order_no||id).padStart(3,'0')+'</h1><p>Klant: '+esc(order.customer_name)+'</p></div><div class="panel"><h2>Opmerking bij bestelling</h2><p>Deze opmerking wordt opgeslagen bij de bestelling en als klantnotitie naar WooCommerce gestuurd voor de factuur.</p><form method="post" action="/admin/orders/'+id+'/note" class="stack"><label>Opmerking<textarea name="notes" rows="4" maxlength="2000" placeholder="Opmerking die op de factuur moet komen">'+esc(order.notes||"")+'</textarea></label><button class="primary">Opmerking opslaan</button></form></div>'+`<div class="panel"><h2>Mandje · items toevoegen</h2><p>Voeg meerdere producten en kosten toe. Pas aantallen en prijzen per regel aan en sla alles in één keer op.</p><form id="catalog-sync-form" method="post" action="/admin/orders/${id}/products/sync"></form><form method="post" action="/admin/orders/${id}/cart" class="stack" id="order-cart"><h3>Producten (${products.length})</h3><button type="submit" form="catalog-sync-form" class="secondary" style="margin:8px 0">WooCommerce-producten opnieuw ophalen ↻</button><div id="cart-products" class="stack"><div class="cart-product row-actions"><select name="product_id"><option value="">Kies een product</option>${products.map(p=>'<option value="'+esc(String(p.id))+'" data-price="'+(Number(p.price_cents||0)/100).toFixed(2)+'">'+esc(p.name||"Product")+' — '+money(p.price_cents||0)+'</option>').join("")}<option value="custom">Aangepast</option></select><input name="custom_name" maxlength="180" placeholder="Naam aangepast product" aria-label="Naam aangepast product" hidden disabled><input name="quantity" type="number" min="1" max="999" value="1" aria-label="Aantal"><input name="price" inputmode="decimal" placeholder="Prijs per stuk (€)" aria-label="Prijs per stuk"><button type="button" class="secondary remove-cart-row">Verwijderen</button></div></div><button type="button" class="secondary" id="add-cart-product">＋ Product toevoegen</button><h3>Kosten / maatwerk</h3><div id="cart-fees" class="stack"><div class="cart-fee row-actions"><input name="fee_name" maxlength="120" placeholder="Omschrijving kosten of maatwerk"><input name="fee_amount" inputmode="decimal" placeholder="Bedrag (€)"><button type="button" class="secondary remove-cart-row">Verwijderen</button></div></div><button type="button" class="secondary" id="add-cart-fee">＋ Kosten / maatwerk toevoegen</button><div><strong>Mandje totaal: <span id="cart-total">€ 0,00</span></strong></div><button class="primary">Alles aan bestelling toevoegen</button></form><script>(function(){const form=document.getElementById("order-cart");if(!form)return;const products=document.getElementById("cart-products"),fees=document.getElementById("cart-fees");const euro=n=>new Intl.NumberFormat("nl-NL",{style:"currency",currency:"EUR"}).format(n);function update(){let total=0;products.querySelectorAll(".cart-product").forEach(r=>{total+=(Number(r.querySelector("[name=quantity]").value)||0)*(Number(String(r.querySelector("[name=price]").value).replace(",", "."))||0)});fees.querySelectorAll(".cart-fee").forEach(r=>{total+=Number(String(r.querySelector("[name=fee_amount]").value).replace(",", "."))||0});document.getElementById("cart-total").textContent=euro(total)}function bind(r){r.querySelectorAll("input,select").forEach(e=>e.addEventListener("input",update));const s=r.querySelector("select");if(s)s.addEventListener("change",()=>{const o=s.selectedOptions[0],custom=s.value==="custom",name=r.querySelector("[name=custom_name]");name.hidden=!custom;name.disabled=!custom;name.required=custom;if(!custom)name.value="";r.querySelector("[name=price]").value=o&&o.dataset.price?o.dataset.price.replace(".", ","):"";update()});r.querySelector(".remove-cart-row").addEventListener("click",()=>{r.remove();update()})}document.getElementById("add-cart-product").addEventListener("click",()=>{const r=products.querySelector(".cart-product").cloneNode(true);r.querySelector("select").value="";r.querySelector("[name=quantity]").value="1";r.querySelector("[name=price]").value="";products.appendChild(r);bind(r);update()});document.getElementById("add-cart-fee").addEventListener("click",()=>{const r=fees.querySelector(".cart-fee").cloneNode(true);r.querySelector("[name=fee_name]").value="";r.querySelector("[name=fee_amount]").value="";fees.appendChild(r);bind(r);update()});form.querySelectorAll(".cart-product,.cart-fee").forEach(bind);update();form.addEventListener("submit",e=>{let valid=true;const p=[...products.querySelectorAll(".cart-product")].some(r=>{const s=r.querySelector("select"),custom=s.value==="custom";if(custom&&!r.querySelector("[name=custom_name]").value.trim())valid=false;return !!s.value});const f=[...fees.querySelectorAll(".cart-fee")].some(r=>r.querySelector("[name=fee_name]").value.trim()||r.querySelector("[name=fee_amount]").value.trim());if(!p&&!f){e.preventDefault();alert("Voeg minimaal één product of kostenregel toe.")}else if(!valid){e.preventDefault();alert("Vul de naam van ieder aangepast product in.")}})})();</script></div>`+'<div class="panel"><h2>Orderregels bewerken</h2><p>Pas productnaam, aantal, prijs en zichtbare productmeta aan. Na opslaan wordt de bestelling direct naar WooCommerce bijgewerkt.</p>'+feePanel+'<div class="table-wrap"><table><thead><tr><th>Product / regel bewerken</th><th>Regeltotaal</th><th></th></tr></thead><tbody>'+lines+'</tbody></table></div>'));
});

app.post("/admin/orders/:id/settings",requireAuth,requireAdmin,(req,res,next)=>{
  orderImageUpload.array("example_images",10)(req,res,error=>{
    if(error)return res.status(400).send(error.message||"Afbeeldingen uploaden is mislukt.");
    next();
  });
},(req,res)=>{
  const id=Number(req.params.id);
  const order=db.prepare("SELECT id,recurring_order_id,example_image_path FROM orders WHERE id=?").get(id);
  if(!order){for(const file of req.files||[])fs.unlink(file.path,()=>{});return res.status(404).send("Bestelling niet gevonden.");}
  const allowReorder=order.recurring_order_id?0:(req.body.allow_reorder==="1"?1:0);
  const files=req.files||[];
  const removeIdsRaw=req.body.remove_image_ids||[];
  const removeIds=[...new Set((Array.isArray(removeIdsRaw)?removeIdsRaw:[removeIdsRaw]).map(Number).filter(n=>Number.isSafeInteger(n)&&n>0))];
  try{
    const tx=db.transaction(()=>{
      db.prepare("UPDATE orders SET allow_reorder=? WHERE id=?").run(allowReorder,id);
      const insert=db.prepare("INSERT INTO order_example_images (order_id,image_path) VALUES (?,?)");
      for(const file of files)insert.run(id,file.filename);
      if(removeIds.length){
        const placeholders=removeIds.map(()=>"?").join(",");
        const owned=db.prepare("SELECT id,image_path FROM order_example_images WHERE order_id=? AND id IN ("+placeholders+")").all(id,...removeIds);
        db.prepare("DELETE FROM order_example_images WHERE order_id=? AND id IN ("+placeholders+")").run(id,...removeIds);
        for(const img of owned)fs.unlink(path.join(orderImageDir,path.basename(img.image_path)),()=>{});
      }
    });
    tx();
  }catch(error){
    for(const file of files)fs.unlink(file.path,()=>{});
    console.error("Order settings save failed:",error.message);
    return res.status(500).send("Bestelinstellingen opslaan is mislukt.");
  }
  res.redirect("/admin/orders/"+id+"/products?settings_saved=1");
});

app.post("/admin/orders/:id/fees",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),name=String(req.body.name||"").trim().slice(0,120),amount=moneyInput(req.body.amount);
 if(!db.prepare("SELECT id FROM orders WHERE id=?").get(id)||!name||!Number.isSafeInteger(amount)||amount<0||amount>100000000)return res.status(400).send("Controleer de fee-omschrijving en het bedrag.");
 db.prepare("INSERT INTO order_fee_lines (order_id,name,amount_cents) VALUES (?,?,?)").run(id,name,amount);
 recalculateOrderTotal(id);
 const synced=await syncWooOrder(id);
 res.redirect("/admin/orders/"+id+"/products"+(synced?"?item_saved=1":"?sync_failed=1"));
});
app.post("/admin/orders/:id/fees/:feeId/edit",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),feeId=Number(req.params.feeId),name=String(req.body.name||"").trim().slice(0,120),amount=moneyInput(req.body.amount);
 const fee=db.prepare("SELECT id FROM order_fee_lines WHERE id=? AND order_id=?").get(feeId,id);
 if(!fee||!name||!Number.isSafeInteger(amount)||amount<0||amount>100000000)return res.status(400).send("Controleer de fee-omschrijving en het bedrag.");
 db.prepare("UPDATE order_fee_lines SET name=?,amount_cents=? WHERE id=? AND order_id=?").run(name,amount,feeId,id);
 recalculateOrderTotal(id);
 const synced=await syncWooOrder(id);
 res.redirect("/admin/orders/"+id+"/products"+(synced?"?item_saved=1":"?sync_failed=1"));
});
app.post("/admin/orders/:id/fees/:feeId/delete",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),feeId=Number(req.params.feeId);
 const deleted=db.prepare("DELETE FROM order_fee_lines WHERE id=? AND order_id=?").run(feeId,id);
 if(!deleted.changes)return res.status(404).send("Fee line niet gevonden.");
 recalculateOrderTotal(id);
 const synced=await syncWooOrder(id);
 res.redirect("/admin/orders/"+id+"/products"+(synced?"?item_deleted=1":"?sync_failed=1"));
});
app.post("/admin/orders/:id/items/:itemId/edit",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),itemId=Number(req.params.itemId),name=String(req.body.name||"").trim().slice(0,180),qty=Number(req.body.quantity),price=moneyInput(req.body.price);
 const item=db.prepare("SELECT oi.id FROM order_items oi WHERE oi.id=? AND oi.order_id=?").get(itemId,id);
 if(!item||!name||!Number.isInteger(qty)||qty<1||qty>999||!Number.isSafeInteger(price)||price<0||price>100000000)return res.status(400).send("Controleer productnaam, aantal en prijs.");
 const meta=[];
 db.transaction(()=>{
  db.prepare("UPDATE order_items SET product_name=?,quantity=?,unit_price_cents=?,meta_data=? WHERE id=? AND order_id=?").run(name,qty,price,JSON.stringify(meta),itemId,id);
  recalculateOrderTotal(id);
 })();
 const result=await syncWooOrder(id);
 res.redirect("/admin/orders/"+id+"/products"+(result?"?item_saved=1":"?sync_failed=1"));
});
app.post("/admin/orders/:id/items/:itemId/delete",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),itemId=Number(req.params.itemId),item=db.prepare("SELECT id FROM order_items WHERE id=? AND order_id=?").get(itemId,id);
 if(!item)return res.status(404).send("Orderregel niet gevonden.");
 db.prepare("DELETE FROM order_items WHERE id=? AND order_id=?").run(itemId,id);
 recalculateOrderTotal(id);
 const result=await syncWooOrder(id);
 res.redirect("/admin/orders/"+id+"/products"+(result?"?item_deleted=1":"?sync_failed=1"));
});
app.post("/admin/orders/:id/note",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),notes=String(req.body.notes||"").trim().slice(0,2000);
 const order=db.prepare("SELECT id,wc_order_id FROM orders WHERE id=?").get(id);
 if(!order)return res.status(404).send("Bestelling niet gevonden.");
 db.prepare("UPDATE orders SET notes=? WHERE id=?").run(notes||null,id);
 if(order.wc_order_id){try{await woo.updateWooOrderNote(order.wc_order_id,notes);}catch(err){console.error("WooCommerce klantnotitie bijwerken mislukt:",err.message);return res.status(502).send("De opmerking is lokaal opgeslagen, maar kon niet naar WooCommerce worden bijgewerkt. Probeer opnieuw.");}}
 res.redirect("/admin/orders/"+id+"/products?note_saved=1");
});
app.post("/admin/orders/:id/cart",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),order=db.prepare("SELECT id FROM orders WHERE id=?").get(id);
 if(!order)return res.status(404).send("Bestelling niet gevonden.");
 const arr=v=>Array.isArray(v)?v:(v===undefined?[]:[v]);
 const productIds=arr(req.body.product_id),quantities=arr(req.body.quantity),prices=arr(req.body.price),customNames=arr(req.body.custom_name),feeNames=arr(req.body.fee_name),feeAmounts=arr(req.body.fee_amount),items=[],fees=[];
 for(let i=0;i<productIds.length;i++){
  const selected=String(productIds[i]||"").trim();if(!selected)continue;
  const qty=Number(quantities[i]),price=moneyInput(prices[i]);
  if(!Number.isInteger(qty)||qty<1||qty>999||!Number.isSafeInteger(price)||price<0||price>100000000)return res.status(400).send("Controleer ieder product, aantal en prijs in het mandje.");
  if(selected==="custom"){
   const name=String(customNames[i]||"").trim().slice(0,180);if(!name)return res.status(400).send("Vul de naam van het aangepaste product in.");
   items.push({product_id:null,product_name:name,quantity:qty,unit_price_cents:price,meta_data:"[]"});continue;
  }
  const product=db.prepare("SELECT * FROM products WHERE id=? AND active=1").get(Number(selected));
  if(!product)return res.status(400).send("Controleer ieder product, aantal en prijs in het mandje.");
  items.push({product_id:product.wc_product_id||("local:"+String(product.id)),product_name:product.name,quantity:qty,unit_price_cents:price,meta_data:product.meta_data||"[]"});
 }
 for(let i=0;i<feeNames.length;i++){
  const name=String(feeNames[i]||"").trim().slice(0,120),raw=String(feeAmounts[i]||"").trim();
  if(!name&&!raw)continue;
  const amount=moneyInput(raw);
  if(!name||!Number.isSafeInteger(amount)||amount<0||amount>100000000)return res.status(400).send("Controleer de omschrijving en het bedrag van iedere kostenregel.");
  fees.push({name,amount_cents:amount});
 }
 if(!items.length&&!fees.length)return res.status(400).send("Voeg minimaal één product of kostenregel toe.");
 db.transaction(()=>{
  const insertItem=db.prepare("INSERT INTO order_items (order_id,product_id,product_name,quantity,unit_price_cents,meta_data) VALUES (?,?,?,?,?,?)");
  for(const x of items)insertItem.run(id,x.product_id,x.product_name,x.quantity,x.unit_price_cents,x.meta_data);
  const insertFee=db.prepare("INSERT INTO order_fee_lines (order_id,name,amount_cents) VALUES (?,?,?)");
  for(const x of fees)insertFee.run(id,x.name,x.amount_cents);
  recalculateOrderTotal(id);
 })();
 const result=await syncWooOrder(id);
 res.redirect("/admin/orders/"+id+"/products"+(result?"?item_saved=1":"?sync_failed=1"));
});
app.post("/admin/orders/:id/custom-item",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),name=String(req.body.name||"").trim().slice(0,180),price=moneyInput(req.body.price),qty=Number(req.body.quantity);
 const order=db.prepare("SELECT id FROM orders WHERE id=?").get(id);
 if(!order||!name||price===null||price<0||!Number.isSafeInteger(price)||!Number.isInteger(qty)||qty<1||qty>999)return res.status(400).send("Ongeldige maatwerkregel. Controleer omschrijving, prijs en aantal.");
 db.prepare("INSERT INTO order_items (order_id,product_id,product_name,quantity,unit_price_cents,meta_data) VALUES (?,NULL,?,?,?,'[]')").run(id,name,qty,price);
 recalculateOrderTotal(id);
 const result=await syncWooOrder(id);
 res.redirect("/admin/orders/"+id+"/products"+(result?"?item_saved=1":"?sync_failed=1"));
});
app.post("/admin/orders/:id/products",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),product=db.prepare("SELECT * FROM products WHERE id=? AND active=1").get(Number(req.body.product_id)),qty=Number(req.body.quantity);
 const order=db.prepare("SELECT id FROM orders WHERE id=?").get(id);if(!order||!product||!Number.isInteger(qty)||qty<1||qty>999)return res.status(400).send("Ongeldige bestelling, productkeuze of aantal.");
 db.prepare("INSERT INTO order_items (order_id,product_id,product_name,quantity,unit_price_cents,meta_data) VALUES (?,?,?,?,?,?)").run(id,product.wc_product_id||("local:"+String(product.id)),product.name,qty,product.price_cents,product.meta_data||"[]");
 recalculateOrderTotal(id);
 const result=await syncWooOrder(id);
 res.redirect("/admin/orders/"+id+"/products"+(result?"?item_saved=1":"?sync_failed=1"));
});
app.get("/admin/subscriptions",requireAuth,requireAdmin,(req,res)=>{
 const subs=db.prepare("SELECT r.*,u.name customer_name,u.email customer_email FROM recurring_orders r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC").all();
 const customers=db.prepare("SELECT id,name FROM users WHERE role='customer' AND active=1 ORDER BY name").all();
 const products=db.prepare("SELECT id,wc_product_id,name,price_cents FROM products WHERE active=1 ORDER BY name").all();
 const options=customers.map(c=>'<option value="'+c.id+'">'+esc(c.name)+'</option>').join("");
 const productOptions=products.map(p=>'<label style="display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--line);border-radius:6px"><input type="checkbox" name="product_ids" value="'+p.id+'" style="width:auto;margin:0"><span>'+esc(p.name)+(p.wc_product_id?' · WooCommerce #'+esc(p.wc_product_id):' · Lokaal')+' — '+money(p.price_cents)+'</span></label>').join("")||'<p>Geen actieve producten gevonden. Synchroniseer eerst WooCommerce-producten.</p>';
 const rows=subs.map(x=>'<tr><td>'+esc(x.name)+'</td><td>'+esc(x.customer_name)+'</td><td>'+esc(x.status)+'</td><td>'+money(x.amount_cents)+'</td><td><a class="danger" href="/admin/subscriptions/'+x.id+'/products">Aanpassen</a> <form method="post" action="/admin/subscriptions/'+x.id+'/delete" style="display:inline" onsubmit="return confirm(&quot;Abonnement verwijderen? Bestaande bestellingen blijven behouden.&quot;)"><button class="danger">Verwijderen</button></form></td></tr>').join("");
 res.send(page(req,"Abonnementen beheren",'<div class="page-title"><h1>Abonnementen</h1><p>Maak een dienst aan voor een bestaande klant.</p></div><div class="panel"><form method="post" action="/admin/subscriptions" class="stack"><label>Klant<select name="user_id" required>'+options+'</select></label><label>Naam dienst<input name="name" maxlength="180" required></label><div class="field"><span class="field-label">Selecteer producten</span><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px;max-height:320px;overflow:auto;padding:2px">'+productOptions+'</div></div><label>Aantal per product<input name="quantity" type="number" min="1" max="999" value="1"></label><label>Bedrag per periode<input name="amount" inputmode="decimal" placeholder="Wordt berekend op basis van producten"></label><label>Periode<select name="interval"><option value="month">Maand</option><option value="year">Jaar</option><option value="week">Week</option></select></label><label>Eerste besteldatum<input name="next_payment" type="date" required></label><button class="primary">Abonnement aanmaken</button></form></div><div class="panel"><table><thead><tr><th>Dienst</th><th>Klant</th><th>Status</th><th>Bedrag</th><th></th></tr></thead><tbody>'+(rows||'<tr><td colspan="5">Nog geen abonnementen.</td></tr>')+'</tbody></table></div>'));
});
app.post("/admin/subscriptions",requireAuth,requireAdmin,(req,res)=>{
 const user=db.prepare("SELECT id FROM users WHERE id=? AND role='customer'").get(Number(req.body.user_id)),name=String(req.body.name||"").trim(),rawIds=req.body.product_ids||[],productIds=[...new Set((Array.isArray(rawIds)?rawIds:[rawIds]).map(x=>Number(x)).filter(Number.isSafeInteger))],products=productIds.length?db.prepare("SELECT * FROM products WHERE active=1 AND id IN ("+productIds.map(()=>"?").join(",")+")").all(...productIds):[],qty=Number(req.body.quantity||1),enteredAmount=String(req.body.amount||"").trim(),amount=enteredAmount?moneyInput(enteredAmount):null,interval=["week","month","year"].includes(req.body.interval)?req.body.interval:"month",next=String(req.body.next_payment||"");
 if(!user||!name||products.length!==productIds.length||!Number.isInteger(qty)||qty<1||qty>999||amount!==null&&(!Number.isSafeInteger(amount)||amount<0)||!next||next&&!/^\d{4}-\d{2}-\d{2}$/.test(next))return res.status(400).send("Controleer de abonnementsgegevens, de geselecteerde producten en de eerste besteldatum.");
 const total=products.length?products.reduce((sum,p)=>sum+p.price_cents*qty,0):(amount??0);
 const tx=db.transaction(()=>{const result=db.prepare("INSERT INTO recurring_orders (user_id,name,amount_cents,interval,next_payment) VALUES (?,?,?,?,?)").run(user.id,name,total,interval,next||null);const insert=db.prepare("INSERT INTO recurring_order_items (recurring_order_id,product_id,product_name,quantity,unit_price_cents) VALUES (?,?,?,?,?)");for(const product of products){const recurringProductId=product.wc_product_id?String(product.wc_product_id):"local:"+String(product.id);insert.run(result.lastInsertRowid,recurringProductId,product.name,qty,product.price_cents);}});
 tx();res.redirect("/admin/subscriptions");
});
app.get("/admin/subscriptions/:id/products",requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id),sub=db.prepare("SELECT r.*,u.name customer_name,u.email customer_email FROM recurring_orders r JOIN users u ON u.id=r.user_id WHERE r.id=?").get(id);if(!sub)return res.status(404).send("Abonnement niet gevonden.");
 const generationToken=crypto.randomBytes(32).toString("hex");db.prepare("UPDATE recurring_orders SET manual_generation_token=? WHERE id=?").run(generationToken,id);
 const products=db.prepare("SELECT id,wc_product_id,name,price_cents,source FROM products WHERE active=1 ORDER BY name").all(),options=products.map(p=>'<label style="display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--line);border-radius:6px"><input type="checkbox" name="product_ids" value="'+p.id+'" style="width:auto;margin:0"><span>'+esc(p.name)+(p.wc_product_id?' · WooCommerce #'+esc(p.wc_product_id):' · Lokaal')+' — '+money(p.price_cents)+'</span></label>').join("")||'<p>Geen actieve producten gevonden.</p>';
 const lines=db.prepare("SELECT * FROM recurring_order_items WHERE recurring_order_id=?").all(id).map(x=>'<tr><td>'+esc(x.product_name)+'</td><td>'+x.quantity+'</td><td><form method="post" action="/admin/subscriptions/'+id+'/items/'+x.id+'/price" style="display:flex;gap:8px;align-items:center"><input name="price" inputmode="decimal" value="'+(x.unit_price_cents/100).toFixed(2).replace(".",",") +'" aria-label="Prijs per stuk" style="max-width:110px"><button class="secondary">Prijs opslaan</button></form></td></tr>').join("");
 res.send(page(req,"Abonnement beheren",(req.query.email_resent?'<div class="success">E-mailadres opgeslagen. De nieuwste bestellingsmail is automatisch opnieuw verstuurd naar het nieuwe adres.</div>':req.query.email_resend_failed?'<div class="alert">E-mailadres opgeslagen, maar opnieuw versturen is mislukt. Bekijk Mail logs voor de foutmelding.</div>':req.query.email_updated?'<div class="success">E-mailadres opgeslagen. Er was nog geen bestelling om opnieuw te mailen.</div>':'')+'<div class="page-title"><h1>Abonnement beheren</h1><p>'+esc(sub.name)+' · '+esc(sub.customer_name)+'</p></div><div class="panel"><h2>E-mailadres voor dit abonnement</h2><p>Dit adres wordt alleen gebruikt voor e-mails over dit abonnement. Het account-e-mailadres blijft ongewijzigd.</p><form method="post" action="/admin/subscriptions/'+id+'/email" class="stack"><label>Ontvanger e-mails<input type="email" name="email_override" value="'+esc(sub.email_override||"")+'" placeholder="'+esc(sub.customer_email||"")+'"></label><button class="primary">E-mailadres opslaan</button></form></div><div class="panel"><h2>Volgende besteldatum aanpassen</h2><form method="post" action="/admin/subscriptions/'+id+'/date" class="stack"><label>Volgende besteldatum<input type="date" name="next_payment" value="'+esc(sub.next_payment||"")+'" required></label><button class="primary">Datum opslaan</button></form></div><div class="panel"><h2>Handmatig bestelling aanmaken</h2><p>Maakt direct een bestelling met de gekoppelde producten. De volgende besteldatum verandert hierdoor niet.</p><form method="post" action="/admin/subscriptions/'+id+'/generate" onsubmit="return confirm(&quot;Weet je zeker dat je nu een bestelling wilt aanmaken?&quot;)"><input type="hidden" name="generation_token" value="'+generationToken+'"><button class="primary">Nu bestelling aanmaken</button></form></div><div class="panel"><h2>Producten toevoegen</h2><form method="post" action="/admin/subscriptions/'+id+'/products" class="stack"><div class="field"><span class="field-label">Selecteer producten</span><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px;max-height:320px;overflow:auto;padding:2px">'+options+'</div></div><label>Aantal per product<input name="quantity" type="number" min="1" max="999" value="1" required></label><button class="primary">Producten toevoegen</button></form></div><div class="panel"><h2>Gekoppelde producten</h2><table><thead><tr><th>Product</th><th>Aantal</th><th>Prijs per stuk</th></tr></thead><tbody>'+(lines||'<tr><td colspan="3">Nog geen producten gekoppeld.</td></tr>')+'</tbody></table></div>'));
});
app.post("/admin/subscriptions/:id/email",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),email=String(req.body.email_override||"").trim();
 const sub=db.prepare("SELECT id FROM recurring_orders WHERE id=?").get(id);
 if(!sub)return res.status(404).send("Abonnement niet gevonden.");
 if(email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).send("Vul een geldig e-mailadres in of laat het veld leeg.");
 db.prepare("UPDATE recurring_orders SET email_override=? WHERE id=?").run(email||null,id);
 const latestOrder=db.prepare("SELECT id FROM orders WHERE recurring_order_id=? ORDER BY id DESC LIMIT 1").get(id);
 if(!latestOrder)return res.redirect("/admin/subscriptions/"+id+"/products?email_updated=1");
 const order=loadMailOrder(latestOrder.id);
 if(!order||!order.email)return res.redirect("/admin/subscriptions/"+id+"/products?email_resend_failed=1");
 console.log("Subscription override mail: subscription="+id+", order="+latestOrder.id+", recipient="+order.email);
 const result=await sendLoggedMail({type:"new_order",to:order.email,orderId:latestOrder.id});
 res.redirect("/admin/subscriptions/"+id+"/products?"+(result.success?"email_resent=1":"email_resend_failed=1"));
});
app.post("/admin/subscriptions/:id/delete",requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id);
 const remove=db.transaction(()=>{db.prepare("DELETE FROM recurring_order_reminders WHERE recurring_order_id=?").run(id);db.prepare("DELETE FROM recurring_order_items WHERE recurring_order_id=?").run(id);return db.prepare("DELETE FROM recurring_orders WHERE id=?").run(id);});
 const result=remove();if(!result.changes)return res.status(404).send("Abonnement niet gevonden.");
 res.redirect("/admin/subscriptions?deleted=1");
});
app.post("/admin/subscriptions/:id/date",requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id),next=String(req.body.next_payment||"");
 if(!/^\d{4}-\d{2}-\d{2}$/.test(next)||!db.prepare("SELECT id FROM recurring_orders WHERE id=?").get(id))return res.status(400).send("Ongeldige besteldatum of abonnement.");
 db.prepare("UPDATE recurring_orders SET next_payment=?,last_generated_for=CASE WHEN last_generated_for>=? THEN NULL ELSE last_generated_for END WHERE id=?").run(next,next,id);
 res.redirect("/admin/subscriptions/"+id+"/products");
});
app.post("/admin/subscriptions/:id/generate",requireAuth,requireAdmin,async(req,res)=>{
 const id=Number(req.params.id),token=String(req.body.generation_token||"");
 if(!/^[a-f0-9]{64}$/.test(token))return res.status(409).send("Dit verzoek is al verwerkt of verlopen. Open het abonnement opnieuw om een nieuwe bestelling aan te maken.");
 const createOnce=db.transaction(()=>{
  const sub=db.prepare("SELECT * FROM recurring_orders WHERE id=?").get(id);
  if(!sub)return {error:"not_found"};
  const consumed=db.prepare("UPDATE recurring_orders SET manual_generation_token=NULL WHERE id=? AND manual_generation_token=?").run(id,token);
  if(!consumed.changes)return {error:"duplicate"};
  const items=db.prepare("SELECT * FROM recurring_order_items WHERE recurring_order_id=?").all(id);
  if(!items.length)return {error:"no_items"};
  const lines=items.map(x=>({product_id:x.product_id,product_name:x.product_name,quantity:x.quantity,unit_price_cents:x.unit_price_cents}));
  const orderId=createOrder(sub.user_id,lines,null,"Handmatig aangemaakte bestelling voor abonnement: "+sub.name,id);
  return {orderId};
 });
 let result;
 try{result=createOnce();}catch(err){console.error("Manual subscription order failed:",err.message);return res.status(502).send("Bestelling kon niet worden aangemaakt: "+esc(err.message));}
 if(result.error==="not_found")return res.status(404).send("Abonnement niet gevonden.");
 if(result.error==="duplicate")return res.status(409).send("Deze bestelling is al aangemaakt. Er is geen tweede bestelling aangemaakt.");
 if(result.error==="no_items")return res.status(400).send("Koppel eerst minimaal één product aan dit abonnement.");
 const orderId=result.orderId;
 queueOrderIntegrations(orderId);
 res.redirect("/admin/subscriptions/"+id+"/products?order_created=1");
});
app.post("/admin/subscriptions/:id/items/:itemId/price",requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id),itemId=Number(req.params.itemId),price=moneyInput(req.body.price);
 const item=db.prepare("SELECT id FROM recurring_order_items WHERE id=? AND recurring_order_id=?").get(itemId,id);
 if(!item||!Number.isSafeInteger(price)||price<0||price>100000000)return res.status(400).send("Ongeldige prijs of productkoppeling.");
 const tx=db.transaction(()=>{
  db.prepare("UPDATE recurring_order_items SET unit_price_cents=? WHERE id=? AND recurring_order_id=?").run(price,itemId,id);
  db.prepare("UPDATE recurring_orders SET amount_cents=(SELECT COALESCE(SUM(quantity*unit_price_cents),0) FROM recurring_order_items WHERE recurring_order_id=?) WHERE id=?").run(id,id);
 });
 tx();
 res.redirect("/admin/subscriptions/"+id+"/products?price_updated=1");
});
app.post("/admin/subscriptions/:id/products",requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id),sub=db.prepare("SELECT id FROM recurring_orders WHERE id=?").get(id),rawIds=req.body.product_ids||[],productIds=[...new Set((Array.isArray(rawIds)?rawIds:[rawIds]).map(x=>Number(x)).filter(Number.isSafeInteger))],products=productIds.length?db.prepare("SELECT * FROM products WHERE active=1 AND id IN ("+productIds.map(()=>"?").join(",")+")").all(...productIds):[],qty=Number(req.body.quantity);
 if(!sub||!products.length||products.length!==productIds.length||!Number.isInteger(qty)||qty<1||qty>999)return res.status(400).send("Selecteer minimaal één geldig product en controleer het aantal.");
 const tx=db.transaction(()=>{const insert=db.prepare("INSERT INTO recurring_order_items (recurring_order_id,product_id,product_name,quantity,unit_price_cents) VALUES (?,?,?,?,?)");for(const p of products){const recurringProductId=p.wc_product_id?String(p.wc_product_id):"local:"+String(p.id);insert.run(id,recurringProductId,p.name,qty,p.price_cents);}db.prepare("UPDATE recurring_orders SET amount_cents=(SELECT COALESCE(SUM(quantity*unit_price_cents),0) FROM recurring_order_items WHERE recurring_order_id=?) WHERE id=?").run(id,id);});
 tx();res.redirect("/admin/subscriptions/"+id+"/products");
});
app.get("/admin/costs",requireAuth,requireAdmin,(req,res)=>res.redirect("/admin"));

app.get("/health",async(_req,res)=>{const redisStatus=await redis.healthCheck();res.json({ok:true,redis:redisStatus});});
app.use((err,req,res,next)=>{console.error(err);res.status(500).send("Er is iets misgegaan.");});
function businessDate(){
 const parts=new Intl.DateTimeFormat("en-GB",{timeZone:process.env.BUSINESS_TIME_ZONE||"Europe/Amsterdam",year:"numeric",month:"2-digit",day:"2-digit"}).formatToParts(new Date());
 const value={};for(const part of parts)if(part.type!=="literal")value[part.type]=part.value;
 return value.year+"-"+value.month+"-"+value.day;
}

let wooBillingSyncRunning=false;
async function syncWooCustomerBilling(){
 if(wooBillingSyncRunning)return {busy:true,checked:0,updated:0,failed:0};
 wooBillingSyncRunning=true;
 const stats={busy:false,checked:0,updated:0,failed:0};
 try{
  const customers=db.prepare("SELECT id,wc_customer_id FROM users WHERE role='customer' AND wc_customer_id IS NOT NULL AND wc_customer_id != '' ORDER BY id").all();
  for(const user of customers){
   stats.checked++;
   try{
    const customer=await woo.getCustomer(user.wc_customer_id);
    const billing=customer&&customer.billing?customer.billing:{};
    const value=(key,fallback="")=>String(billing[key]??fallback).trim();
    const first=value("first_name",customer.first_name||"");
    const last=value("last_name",customer.last_name||"");
    db.prepare(`UPDATE users SET
     billing_first_name=?,billing_last_name=?,billing_company=?,billing_address_1=?,
     billing_address_2=?,billing_postcode=?,billing_city=?,billing_state=?,
     billing_country=?,billing_phone=?
     WHERE id=? AND wc_customer_id=?`).run(
      first,last,value("company"),value("address_1"),value("address_2"),
      value("postcode"),value("city"),value("state"),value("country","NL").toUpperCase().slice(0,2),
      value("phone"),user.id,String(user.wc_customer_id)
     );
    stats.updated++;
   }catch(error){
    stats.failed++;
    console.error("WooCommerce factuurgegevens synchroniseren mislukt voor klant "+user.wc_customer_id+":",error.response?.data?.message||error.message);
   }
  }
  if(stats.checked)console.log("WooCommerce factuurgegevens gesynchroniseerd:",JSON.stringify(stats));
 }catch(error){stats.failed++;console.error("WooCommerce factuurgegevens synchronisatie:",error.message);}
 finally{wooBillingSyncRunning=false;}
 return stats;
}

let recurringSchedulerRunning=false;
async function processRecurringOrders(){
 if(recurringSchedulerRunning)return;
 recurringSchedulerRunning=true;
 const today=businessDate();
 const createThrough=shiftDate(today,14);
 try{
  // Maak iedere geplande order 14 dagen vóór de besteldatum aan.
  const due=db.prepare("SELECT * FROM recurring_orders WHERE status='active' AND next_payment IS NOT NULL AND next_payment<=? AND (last_generated_for IS NULL OR last_generated_for<next_payment) ORDER BY id").all(createThrough);
  for(const sub of due){
   const items=db.prepare("SELECT * FROM recurring_order_items WHERE recurring_order_id=?").all(sub.id);
   if(!items.length){console.warn("Terugkerende bestelling "+sub.id+" overgeslagen: geen orderregels.");continue;}
   try{
    const tx=db.transaction(()=>{
     const current=db.prepare("SELECT * FROM recurring_orders WHERE id=? AND status='active' AND next_payment=? AND (last_generated_for IS NULL OR last_generated_for<next_payment)").get(sub.id,sub.next_payment);
     if(!current)return null;
     const scheduledDate=current.next_payment;
     const lines=items.map(x=>({product_id:x.product_id,product_name:x.product_name,quantity:x.quantity,unit_price_cents:x.unit_price_cents}));
     const orderId=createOrder(current.user_id,lines,null,"Automatisch terugkerende bestelling: "+current.name+" (gepland voor "+scheduledDate+")",current.id);
     const insertReminder=db.prepare("INSERT OR IGNORE INTO recurring_order_reminders (recurring_order_id,order_id,scheduled_for,days_before,status) VALUES (?,?,?,?, 'pending')");
     for(const reminder of reminderSchedule(scheduledDate)){
      insertReminder.run(current.id,orderId,reminder.sendOn,reminder.daysBefore);
     }
     db.prepare("UPDATE recurring_orders SET last_generated_for=?,next_payment=? WHERE id=?").run(scheduledDate,addBillingPeriod(scheduledDate,current.interval),current.id);
     return {orderId,scheduledDate};
    });
    const created=tx();
    if(created){
     await syncWooOrder(created.orderId);
     await sendOrderWebhook(created.orderId);
     await sendOrderCreatedEmail(created.orderId);
     console.log("Terugkerende bestelling "+created.orderId+" aangemaakt voor "+created.scheduledDate+" (14 dagen vooraf).");
    }
   }catch(err){console.error("Terugkerende bestelling mislukt voor "+sub.id+":",err.message);}
  }

  // Herstel vastgelopen claims na een onverwachte processtop.
  db.prepare("UPDATE recurring_order_reminders SET status='pending',claimed_at=NULL WHERE status='sending' AND claimed_at<?").run(Date.now()-10*60*1000);
  const reminders=db.prepare(
   "SELECT r.id,r.order_id,r.scheduled_for,r.days_before,o.user_id,o.status AS order_status,o.total_cents,o.currency,o.local_order_no,o.wc_order_number,o.wc_order_id,COALESCE(NULLIF(ro.email_override,''),u.email) email " +
   "FROM recurring_order_reminders r JOIN orders o ON o.id=r.order_id JOIN users u ON u.id=o.user_id LEFT JOIN recurring_orders ro ON ro.id=r.recurring_order_id " +
   "WHERE r.status='pending' AND r.scheduled_for<=? ORDER BY r.scheduled_for,r.id"
  ).all(today);
  for(const reminder of reminders){
   const claimed=db.prepare("UPDATE recurring_order_reminders SET status='sending',claimed_at=?,last_error=NULL WHERE id=? AND status='pending'").run(Date.now(),reminder.id);
   if(!claimed.changes)continue;
   try{
    // Controleer de actuele WooCommerce-status vlak vóór verzending; de lokale kopie kan achterlopen.
    let currentStatus="";
    let paymentDate="";
    if(reminder.wc_order_id){
     const liveOrder=await woo.getOrder(reminder.wc_order_id);
     currentStatus=String(liveOrder.status||"").toLowerCase();
     paymentDate=String(liveOrder.date_paid||"");
     db.prepare("UPDATE orders SET wc_status=? WHERE id=?").run(currentStatus,reminder.order_id);
    }
    const localStatus=String(reminder.order_status||"").toLowerCase();
    const paidStatuses=new Set(["processing","completed","paid","betaald"]);
    const terminalStatuses=new Set(["refunded","cancelled","canceled"]);
    if(paidStatuses.has(currentStatus)||paidStatuses.has(localStatus)||paymentDate||
       terminalStatuses.has(currentStatus)||terminalStatuses.has(localStatus)){
     const skippedType=reminder.days_before===7?"reminder_7":"reminder_3";
     db.prepare("INSERT INTO mail_logs (email_type,order_id,recipient,subject,status,error,days_before,order_date) VALUES (?,?,?,?, 'skipped',?,?,?)")
      .run(skippedType,reminder.order_id,reminder.email,mailSubject(skippedType,{number:supplyOrderNumber(reminder.local_order_no||reminder.order_id)}),"Herinnering overgeslagen: bestelling is betaald of afgesloten.",reminder.days_before,reminder.scheduled_for);
     db.prepare("UPDATE recurring_order_reminders SET status='skipped',claimed_at=NULL,last_error=? WHERE id=?")
      .run("Herinnering overgeslagen: bestelling is betaald of afgesloten.",reminder.id);
     console.log("Bestelherinnering overgeslagen voor order "+reminder.order_id+" (betaald/afgesloten).");
     continue;
    }
    const mailResult=await sendLoggedMail({
     type:reminder.days_before===7?"reminder_7":"reminder_3",
     to:reminder.email,
     orderId:reminder.order_id,
     daysBefore:reminder.days_before,
     orderDate:reminder.scheduled_for
    });
    if(mailResult.success){
     db.prepare("UPDATE recurring_order_reminders SET status='sent',sent_at=CURRENT_TIMESTAMP,claimed_at=NULL,last_error=NULL WHERE id=?").run(reminder.id);
     console.log("Bestelherinnering ("+reminder.days_before+" dagen) verzonden voor order "+reminder.order_id+".");
    }else{
     db.prepare("UPDATE recurring_order_reminders SET status='pending',claimed_at=NULL,last_error=? WHERE id=?").run("E-mailverzending mislukt. Bekijk Mail logs voor de details.",reminder.id);
    }
   }catch(err){
    db.prepare("UPDATE recurring_order_reminders SET status='pending',claimed_at=NULL,last_error=? WHERE id=?").run(String(err.message||err).slice(0,1000),reminder.id);
    console.error("Bestelherinnering mislukt voor order "+reminder.order_id+":",err.message);
   }
  }
 }finally{recurringSchedulerRunning=false;}
}
setTimeout(()=>processRecurringOrders().catch(err=>console.error("Recurring scheduler:",err.message)),5000);
setInterval(()=>processRecurringOrders().catch(err=>console.error("Recurring scheduler:",err.message)),60000).unref();
setTimeout(()=>syncDeletedWooOrders(),15000).unref();
setInterval(()=>syncDeletedWooOrders(),300000).unref();
setTimeout(()=>syncWooCustomerBilling(),20000).unref();
setInterval(()=>syncWooCustomerBilling(),300000).unref();
app.listen(PORT, "0.0.0.0", ()=>console.log(`Bendemen Supply Panel draait op poort ${PORT}`));
