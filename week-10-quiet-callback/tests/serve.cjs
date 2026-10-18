'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..');
function server(){return http.createServer((req,res)=>{let file;try{const url=new URL(req.url,'http://localhost');file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));}catch{res.writeHead(400).end();return;}if(!file.startsWith(root+path.sep)){res.writeHead(403).end();return;}fs.readFile(file,(err,data)=>{if(err){res.writeHead(404).end('Not found');return;}res.setHeader('Content-Type',({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json'}[path.extname(file)]||'text/plain; charset=utf-8'));res.end(data);});});}
module.exports=server;
if(require.main===module)server().listen(4173,'127.0.0.1',()=>console.log('Quiet Callback: http://127.0.0.1:4173'));
