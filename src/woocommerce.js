const axios=require("axios");
function isWooProductId(value){return /^\d+$/.test(String(value||""));}
function config(){const base=(process.env.WC_STORE_URL||"").replace(/\/$/,"");if(!base||!process.env.WC_CONSUMER_KEY||!process.env.WC_CONSUMER_SECRET)throw new Error("WooCommerce API configuration is incomplete");return{base,key:process.env.WC_CONSUMER_KEY,secret:process.env.WC_CONSUMER_SECRET};}
async function request(endpoint,method="GET",data){
 const c=config(),auth=Buffer.from(c.key+":"+c.secret).toString("base64");
 const timeout=Math.max(5000,Math.min(120000,Number(process.env.WC_API_TIMEOUT_MS)||60000));
 try{
  const response=await axios({url:`${c.base}/wp-json/wc/v3/${endpoint}`,method,data,headers:{Authorization:`Basic ${auth}`},timeout});
  return response.data;
 }catch(err){
  const responseData=err.response?.data;
  const detail={
   code:err.code||null,
   status:err.response?.status||null,
   message:err.message,
   wooCode:responseData?.code||null,
   wooMessage:responseData?.message||null,
   wooData:responseData?.data||null
  };
  console.error("WooCommerce API request failed:",{method,endpoint,...detail,timeoutMs:timeout,baseUrl:c.base});
  throw err;
 }
}
async function listProducts(page=1,perPage=100){return request(`products?status=any&per_page=${Math.min(100,perPage)}&page=${page}`);}
async function searchCustomers(query,page=1){return request(`customers?search=${encodeURIComponent(query)}&per_page=30&page=${page}`);}
async function getCustomer(id){return request(`customers/${encodeURIComponent(id)}`);}
async function updateWooCustomerBilling(id,billing){return request(`customers/${encodeURIComponent(id)}`,"PUT",{billing});}
async function createExpenseOrder(expense){
 const payload={
  status:"on-hold",
  set_paid:false,
  billing:{first_name:"Bendemen",last_name:"Supply Panel",email:process.env.WC_EXPENSE_EMAIL||"info@bendemen.nl"},
  line_items:[],
  fee_lines:[{name:`Supply Panel kosten: ${expense.name}`,tax_status:"none",total:(expense.amount_cents/100).toFixed(2)}],
  meta_data:[{key:"_bendemen_supply_expense",value:"1"},{key:"_bendemen_expense_id",value:String(expense.id)}]
 };
 return request("orders","POST",payload);
}
function isExcludedProductMetaKey(key){
 const normalized=String(key||"").trim().toLowerCase();
 return normalized.startsWith("_")||normalized.startsWith("rank_math")||normalized.startsWith("rank-math")||normalized.startsWith("rankmath");
}
function normalizeLineMeta(raw){
 let values=[];try{values=Array.isArray(raw)?raw:JSON.parse(raw||"[]");}catch(_){values=[];}
 return values.filter(x=>x&&typeof x.key==="string"&&!isExcludedProductMetaKey(x.key)&&x.value!==undefined).map(x=>({key:x.key,value:x.value}));
}
function buildWooLineItem(item,existingLine){
 const total=(item.quantity*item.unit_price_cents/100).toFixed(2);
 const wcProductId=item.product_id&&isWooProductId(item.product_id)?String(item.product_id):null;
 return {
  ...(existingLine?.id?{id:existingLine.id}:{}),
  // WooCommerce orderregel blijft een line_item, ook zonder catalogusproduct.
  // Gebruik expliciet product_id: 0 voor handmatige/aangepaste producten;
  // stuur deze nooit als fee_line.
  product_id:wcProductId?Number(wcProductId):0,
  name:item.product_name,
  quantity:item.quantity,
  subtotal:total,
  total,
  meta_data:[]
 };
}
function findExistingWooLine(item,oldItems,usedItemIds){
 const wcProductId=item.product_id&&isWooProductId(item.product_id)?String(item.product_id):null;
 return oldItems.find(line=>!usedItemIds.has(line.id)&&(
  wcProductId?String(line.product_id)===wcProductId:
   !line.product_id&&String(line.name||"").trim()===String(item.product_name||"").trim()
 ));
}
async function createWooOrder(order,items,fees=[]){
 const line_items=[],fee_lines=[];
 for(const item of items)line_items.push(buildWooLineItem(item));
 for(const fee of fees)fee_lines.push({name:fee.name,tax_status:"none",total:(fee.amount_cents/100).toFixed(2)});
 const payload={
  status:"pending",
  set_paid:false,
  customer_id:order.wc_customer_id?Number(order.wc_customer_id):0,
  billing:{email:order.customer_email,first_name:order.billing_first_name||"",last_name:order.billing_last_name||"",company:order.billing_company||"",address_1:order.billing_address_1||"",address_2:order.billing_address_2||"",postcode:order.billing_postcode||"",city:order.billing_city||"",state:order.billing_state||"",country:order.billing_country||"NL",phone:order.billing_phone||""},
  line_items,
  fee_lines,
  meta_data:[{key:"_bendemen_supply_panel_order",value:"1"},{key:"_bendemen_local_order_id",value:String(order.id)},{key:"_wcpdf_invoice_notes",value:String(order.notes||"")}]
 };
 return request("orders","POST",payload);
}
async function updateWooOrder(wcOrderId,items,fees=[]){
 const existing=await request(`orders/${encodeURIComponent(wcOrderId)}`);
 const oldItems=Array.isArray(existing.line_items)?existing.line_items:[];
 const oldFees=Array.isArray(existing.fee_lines)?existing.fee_lines:[];
 const line_items=[],fee_lines=[],usedItemIds=new Set(),usedFeeIds=new Set();
 for(const item of items){
  const match=findExistingWooLine(item,oldItems,usedItemIds);
  if(match)usedItemIds.add(match.id);
  line_items.push(buildWooLineItem(item,match));
 }
 for(const fee of fees){
  const match=oldFees.find(line=>line.name===fee.name&&!usedFeeIds.has(line.id));
  if(match)usedFeeIds.add(match.id);
  fee_lines.push({...(match?{id:match.id}:{}),name:fee.name,tax_status:"none",total:(fee.amount_cents/100).toFixed(2)});
 }
 // WooCommerce verwijdert bestaande orderregels via delete:true in de
 // order-update payload. Losse /fee_lines/{id} DELETE-routes zijn niet
 // beschikbaar op iedere WooCommerce REST-installatie en kunnen 404 geven.
 for(const line of oldItems){
  if(!usedItemIds.has(line.id))line_items.push({id:line.id,delete:true});
 }
 for(const line of oldFees){
  if(!usedFeeIds.has(line.id))fee_lines.push({id:line.id,delete:true});
 }
 return request(`orders/${encodeURIComponent(wcOrderId)}`,"PUT",{line_items,fee_lines});
}
async function updateWooOrderNote(wcOrderId,notes){return request(`orders/${encodeURIComponent(wcOrderId)}`,"PUT",{meta_data:[{key:"_wcpdf_invoice_notes",value:String(notes||"")}]});}
async function createWooSubscription(subscription,items){
 const line_items=[],fee_lines=[];
 for(const item of items){
  const wcProductId=item.product_id&&isWooProductId(item.product_id)?String(item.product_id):null;
  line_items.push(buildWooLineItem(item));
 }
 if(!line_items.length&&!fee_lines.length)throw new Error("Abonnement bevat geen regels.");
 const payload={status:"pending",customer_id:subscription.wc_customer_id?Number(subscription.wc_customer_id):0,billing:{email:subscription.customer_email,first_name:subscription.customer_name},billing_period:subscription.interval==="year"?"year":subscription.interval==="week"?"week":"month",billing_interval:1,start_date:subscription.next_payment||new Date().toISOString().slice(0,10),line_items,fee_lines,meta_data:[{key:"_bendemen_supply_panel_subscription",value:"1"},{key:"_bendemen_local_subscription_id",value:String(subscription.id)}]};
 return request("subscriptions","POST",payload);
}
async function refreshWooOrder(localOrderId){return null;}
async function refreshInvoicePdf(wcOrderId){
 if(!process.env.WPO_WCPDF_API_TOKEN)throw new Error("WPO_WCPDF_API_TOKEN ontbreekt");
 const c=config();
 const response=await axios({url:`${c.base}/wp-json/bendemen/v1/orders/${encodeURIComponent(wcOrderId)}/invoice`,method:"POST",headers:{"X-Bendemen-Invoice-Token":process.env.WPO_WCPDF_API_TOKEN},timeout:60000});
 const data=response.data||{};
 const buffer=Buffer.from(String(data.pdf_base64||""),"base64");
 if(buffer.subarray(0,5).toString()!=="%PDF-")throw new Error("WP Overnight returned an invalid refreshed PDF");
 return{buffer,filename:String(data.filename||`invoice-${wcOrderId}.pdf`)};
}
async function getInvoicePdf(wcOrderId){
 const c=config();
 if(!process.env.WPO_WCPDF_API_TOKEN)throw new Error("WPO_WCPDF_API_TOKEN ontbreekt");
 // This is our own REST endpoint, not the WooCommerce REST API.
 // Do not send WooCommerce consumer keys as HTTP Basic credentials here:
 // WordPress may interpret them as a username/password and return a login error.
 const response=await axios({url:`${c.base}/wp-json/bendemen/v1/orders/${encodeURIComponent(wcOrderId)}/invoice`,method:"GET",headers:{"X-Bendemen-Invoice-Token":process.env.WPO_WCPDF_API_TOKEN},timeout:60000});
 if(!response.data||typeof response.data.pdf_base64!=="string")throw new Error(response.data?.message||"WP Overnight retourneerde geen PDF");
 const pdf=Buffer.from(response.data.pdf_base64,"base64");
 if(pdf.subarray(0,5).toString()!=="%PDF-")throw new Error("WP Overnight retourneerde geen geldige PDF");
 // Attach the official WP Overnight invoice number for download filenames.
 pdf.filename=String(response.data.filename||"").replace(/[\\/\\\\\\r\\n"]/g,"").replace(/^factuu?r?-(?=FACTUUR-)/i,"").slice(0,180)||`invoice-${wcOrderId}.pdf`;
 return pdf;
}
async function getOrder(wcOrderId){return request(`orders/${encodeURIComponent(wcOrderId)}`);}
module.exports={request,getOrder,listProducts,searchCustomers,getCustomer,createExpenseOrder,createWooOrder,updateWooOrder,updateWooOrderNote,createWooSubscription,refreshWooOrder,getInvoicePdf,refreshInvoicePdf,isWooProductId,buildWooLineItem};
