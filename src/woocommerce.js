const axios=require("axios");
const http=require("http");
const https=require("https");
const httpAgent=new http.Agent({keepAlive:true,maxSockets:5,maxFreeSockets:2,timeout:30000});
const httpsAgent=new https.Agent({keepAlive:true,maxSockets:5,maxFreeSockets:2,timeout:30000});

function isWooProductId(value){return /^\d+$/.test(String(value||""));}
function config(){
 const base=(process.env.WC_STORE_URL||"").replace(/\/$/,"");
 const secret=process.env.WC_BRIDGE_SECRET||"";
 if(!base||secret.length<40)throw new Error("Supply Bridge-configuratie ontbreekt. Stel WC_STORE_URL en WC_BRIDGE_SECRET in.");
 return{base,secret};
}
async function request(endpoint,method="GET",data){
 const c=config();
 const timeout=Math.max(5000,Math.min(120000,Number(process.env.WC_API_TIMEOUT_MS)||20000));
 try{
  const response=await axios({
   url:`${c.base}/wp-json/bendemen-supply/v1/${String(endpoint).replace(/^\//,"")}`,
   method,data,headers:{"X-Bendemen-Supply-Key":c.secret,"Content-Type":"application/json"},
   timeout,httpAgent,httpsAgent,maxRedirects:3
  });
  return response.data;
 }catch(err){
  const responseData=err.response?.data;
  console.error("Supply Bridge request failed:",{
   method,endpoint,code:err.code||null,status:err.response?.status||null,
   message:err.message,bridgeCode:responseData?.code||null,
   bridgeMessage:responseData?.message||null,timeoutMs:timeout,baseUrl:c.base
  });
  throw new Error(responseData?.message||err.message||"Supply Bridge request failed");
 }
}
async function listProducts(page=1,perPage=100){return request(`products?status=any&per_page=${Math.min(100,perPage)}&page=${page}`);}
async function searchCustomers(query,page=1){return request(`customers?search=${encodeURIComponent(query)}&per_page=30&page=${page}`);}
async function getCustomer(id){return request(`customers/${encodeURIComponent(id)}`);}
async function updateWooCustomerBilling(id,billing){return request(`customers/${encodeURIComponent(id)}`,"PUT",{billing});}
async function createExpenseOrder(expense){
 return request("orders","POST",{
  status:"on-hold",set_paid:false,
  billing:{first_name:"Bendemen",last_name:"Supply Panel",email:process.env.WC_EXPENSE_EMAIL||"info@bendemen.nl"},
  line_items:[],
  fee_lines:[{name:`Supply Panel kosten: ${expense.name}`,tax_status:"none",total:(expense.amount_cents/100).toFixed(2)}],
  meta_data:[{key:"_bendemen_supply_expense",value:"1"},{key:"_bendemen_expense_id",value:String(expense.id)}]
 });
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
  ...(wcProductId?{product_id:Number(wcProductId)}:{}),
  name:item.product_name,quantity:item.quantity,subtotal:total,total,meta_data:[]
 };
}
function findExistingWooLine(item,oldItems,usedItemIds){
 const wcProductId=item.product_id&&isWooProductId(item.product_id)?String(item.product_id):null;
 const sameName=line=>String(line.name||"").trim().toLowerCase()===String(item.product_name||"").trim().toLowerCase();
 return oldItems.find(line=>!usedItemIds.has(line.id)&&wcProductId&&String(line.product_id)===wcProductId)
  ||oldItems.find(line=>!usedItemIds.has(line.id)&&sameName(line));
}
async function createWooOrder(order,items,fees=[]){
 const line_items=items.map(item=>buildWooLineItem(item));
 const fee_lines=fees.map(fee=>({name:fee.name,tax_status:"none",total:(fee.amount_cents/100).toFixed(2)}));
 return request("orders","POST",{
  status:"pending",set_paid:false,customer_id:order.wc_customer_id?Number(order.wc_customer_id):0,
  billing:{email:order.customer_email,first_name:order.billing_first_name||"",last_name:order.billing_last_name||"",company:order.billing_company||"",address_1:order.billing_address_1||"",address_2:order.billing_address_2||"",postcode:order.billing_postcode||"",city:order.billing_city||"",state:order.billing_state||"",country:order.billing_country||"NL",phone:order.billing_phone||""},
  line_items,fee_lines,
  meta_data:[{key:"_bendemen_supply_panel_order",value:"1"},{key:"_bendemen_local_order_id",value:String(order.id)},{key:"_wcpdf_invoice_notes",value:String(order.notes||"")}]
 });
}
async function updateWooOrder(wcOrderId,items,fees=[]){
 const existing=await request(`orders/${encodeURIComponent(wcOrderId)}`);
 const oldItems=Array.isArray(existing.line_items)?existing.line_items:[];
 const oldFees=Array.isArray(existing.fee_lines)?existing.fee_lines:[];
 const usedItemIds=new Set(),usedFeeIds=new Set();
 const line_items=items.map(item=>{
  const match=findExistingWooLine(item,oldItems,usedItemIds);
  if(match)usedItemIds.add(match.id);
  return buildWooLineItem(item,match);
 });
 const fee_lines=fees.map(fee=>{
  const match=oldFees.find(line=>line.name===fee.name&&!usedFeeIds.has(line.id));
  if(match)usedFeeIds.add(match.id);
  return{...(match?{id:match.id}:{}),name:fee.name,tax_status:"none",total:(fee.amount_cents/100).toFixed(2)};
 });
 for(const line of oldItems)if(!usedItemIds.has(line.id))line_items.push({id:line.id,quantity:0});
 for(const line of oldFees)if(!usedFeeIds.has(line.id))fee_lines.push({id:line.id,delete:true});
 return request(`orders/${encodeURIComponent(wcOrderId)}`,"PUT",{line_items,fee_lines});
}
async function updateWooOrderNote(wcOrderId,notes){
 return request(`orders/${encodeURIComponent(wcOrderId)}`,"PUT",{meta_data:[{key:"_wcpdf_invoice_notes",value:String(notes||"")}]});
}
async function createWooSubscription(){
 throw new Error("Supply Panel-abonnementen worden lokaal beheerd. Een WooCommerce Subscriptions-plugin is niet vereist of ondersteund.");
}
async function refreshWooOrder(){return null;}
async function invoiceRequest(wcOrderId,method){
 const c=config();
 if(!process.env.WPO_WCPDF_API_TOKEN)throw new Error("WPO_WCPDF_API_TOKEN ontbreekt");
 return axios({
  url:`${c.base}/wp-json/bendemen/v1/orders/${encodeURIComponent(wcOrderId)}/invoice`,
  method,headers:{"X-Bendemen-Invoice-Token":process.env.WPO_WCPDF_API_TOKEN},
  timeout:60000,httpAgent,httpsAgent,maxRedirects:3
 });
}
async function refreshInvoicePdf(wcOrderId){
 const response=await invoiceRequest(wcOrderId,"POST");
 const data=response.data||{},buffer=Buffer.from(String(data.pdf_base64||""),"base64");
 if(buffer.subarray(0,5).toString()!=="%PDF-")throw new Error("WP Overnight returned an invalid refreshed PDF");
 return{buffer,filename:String(data.filename||`invoice-${wcOrderId}.pdf`)};
}
async function getInvoicePdf(wcOrderId){
 const response=await invoiceRequest(wcOrderId,"GET");
 if(!response.data||typeof response.data.pdf_base64!=="string")throw new Error(response.data?.message||"WP Overnight retourneerde geen PDF");
 const pdf=Buffer.from(response.data.pdf_base64,"base64");
 if(pdf.subarray(0,5).toString()!=="%PDF-")throw new Error("WP Overnight retourneerde geen geldige PDF");
 pdf.filename=String(response.data.filename||"").replace(/[\\/\\\\\\r\\n"]/g,"").replace(/^factuu?r?-(?=FACTUUR-)/i,"").slice(0,180)||`invoice-${wcOrderId}.pdf`;
 return pdf;
}
async function getOrder(wcOrderId){return request(`orders/${encodeURIComponent(wcOrderId)}`);}
module.exports={request,getOrder,listProducts,searchCustomers,getCustomer,updateWooCustomerBilling,createExpenseOrder,createWooOrder,updateWooOrder,updateWooOrderNote,createWooSubscription,refreshWooOrder,getInvoicePdf,refreshInvoicePdf,isWooProductId,buildWooLineItem,normalizeLineMeta};
