/**
 * Script Frida Simples para interceptar requisições HTTP
 * Versão simplificada focada em OkHttp (Android) e Fetch API
 */

console.log("[*] Interceptador HTTP Simples iniciado");

// Função para imprimir requisições de forma limpa
function logRequest(type, method, url, headers, body) {
    console.log(`\n[${type}] ${method} ${url}`);
    if (headers && Object.keys(headers).length > 0) {
        console.log("Headers:", JSON.stringify(headers, null, 2));
    }
    if (body) {
        console.log("Body:", body);
    }
}

function logResponse(url, statusCode, response) {
    console.log(`\n[RESPOSTA] ${statusCode} ${url}`);
    if (response) {
        console.log("Response:", response.substring(0, 1000) + (response.length > 1000 ? "..." : ""));
    }
}

// Interceptar OkHttp (Android)
Java.perform(function() {
    try {
        const RealCall = Java.use("okhttp3.RealCall");
        
        RealCall.execute.implementation = function() {
            const request = this.request();
            const url = request.url().toString();
            const method = request.method();
            
            // Capturar headers básicos
            const headers = {};
            try {
                const headerNames = request.headers().names();
                const iterator = headerNames.iterator();
                while (iterator.hasNext()) {
                    const name = iterator.next();
                    headers[name] = request.headers().get(name);
                }
            } catch (e) {}
            
            // Capturar body
            let body = "";
            try {
                const requestBody = request.body();
                if (requestBody) {
                    const buffer = Java.use("okio.Buffer").$new();
                    requestBody.writeTo(buffer);
                    body = buffer.readUtf8();
                }
            } catch (e) {}
            
            logRequest("REQUISIÇÃO", method, url, headers, body);
            
            // Executar requisição
            const response = this.execute();
            const responseCode = response.code();
            
            // Capturar resposta
            let responseBody = "";
            try {
                const respBody = response.body();
                if (respBody) {
                    responseBody = respBody.string();
                    // Recriar response para não quebrar o app
                    const ResponseBody = Java.use("okhttp3.ResponseBody");
                    const newBody = ResponseBody.create(respBody.contentType(), responseBody);
                    const newResponse = response.newBuilder().body(newBody).build();
                    
                    logResponse(url, responseCode, responseBody);
                    return newResponse;
                }
            } catch (e) {}
            
            logResponse(url, responseCode, responseBody);
            return response;
        };
        
        console.log("[+] OkHttp interceptado!");
    } catch (e) {
        console.log("[-] OkHttp não encontrado");
    }
});

// Interceptar Fetch API (React Native/JavaScript)
if (typeof global !== 'undefined' && global.fetch) {
    const originalFetch = global.fetch;
    
    global.fetch = function(url, options) {
        const method = (options && options.method) || 'GET';
        const headers = (options && options.headers) || {};
        const body = (options && options.body) || '';
        
        logRequest("FETCH", method, url.toString(), headers, body);
        
        return originalFetch.apply(this, arguments).then(response => {
            const clonedResponse = response.clone();
            
            clonedResponse.text().then(text => {
                logResponse(url.toString(), response.status, text);
            }).catch(() => {});
            
            return response;
        });
    };
    
    console.log("[+] Fetch API interceptado!");
}

console.log("[*] Pronto! Aguardando requisições HTTP...");