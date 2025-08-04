/**
 * Script Frida para interceptar todas as requisições HTTP
 * Funciona com Android e iOS, interceptando múltiplas bibliotecas de rede
 */

console.log("[*] Iniciando interceptador de requisições HTTP...");

// Função para formatar e imprimir dados
function formatAndPrint(type, data) {
    console.log("\n" + "=".repeat(80));
    console.log(`[${type}] ${new Date().toISOString()}`);
    console.log("=".repeat(80));
    
    if (data.method) console.log(`Método: ${data.method}`);
    if (data.url) console.log(`URL: ${data.url}`);
    if (data.headers) {
        console.log("Headers:");
        for (let key in data.headers) {
            console.log(`  ${key}: ${data.headers[key]}`);
        }
    }
    if (data.body) {
        console.log("Body:");
        console.log(data.body);
    }
    if (data.response) {
        console.log("Resposta:");
        console.log(data.response);
    }
    if (data.statusCode) console.log(`Status Code: ${data.statusCode}`);
    
    console.log("=".repeat(80));
}

// Interceptar OkHttp (Android - muito comum)
try {
    const OkHttpClient = Java.use("okhttp3.OkHttpClient");
    const Request = Java.use("okhttp3.Request");
    const Response = Java.use("okhttp3.Response");
    const ResponseBody = Java.use("okhttp3.ResponseBody");
    
    // Interceptar chamadas do OkHttp
    const RealCall = Java.use("okhttp3.RealCall");
    RealCall.execute.implementation = function() {
        const request = this.request();
        const url = request.url().toString();
        const method = request.method();
        
        // Capturar headers
        const headers = {};
        const headerNames = request.headers().names();
        const headerIterator = headerNames.iterator();
        while (headerIterator.hasNext()) {
            const name = headerIterator.next();
            headers[name] = request.headers().get(name);
        }
        
        // Capturar body da requisição
        let requestBody = "";
        const body = request.body();
        if (body) {
            try {
                const buffer = Java.use("okio.Buffer").$new();
                body.writeTo(buffer);
                requestBody = buffer.readUtf8();
            } catch (e) {
                requestBody = "[Erro ao ler body da requisição]";
            }
        }
        
        formatAndPrint("REQUISIÇÃO", {
            method: method,
            url: url,
            headers: headers,
            body: requestBody
        });
        
        // Executar requisição original
        const response = this.execute();
        
        // Interceptar resposta
        const responseCode = response.code();
        const responseHeaders = {};
        const respHeaderNames = response.headers().names();
        const respHeaderIterator = respHeaderNames.iterator();
        while (respHeaderIterator.hasNext()) {
            const name = respHeaderIterator.next();
            responseHeaders[name] = response.headers().get(name);
        }
        
        // Capturar body da resposta
        let responseBody = "";
        try {
            const respBody = response.body();
            if (respBody) {
                responseBody = respBody.string();
                // Recriar o response body para não quebrar o app
                const newBody = ResponseBody.create(respBody.contentType(), responseBody);
                const newResponse = response.newBuilder().body(newBody).build();
                
                formatAndPrint("RESPOSTA", {
                    url: url,
                    statusCode: responseCode,
                    headers: responseHeaders,
                    response: responseBody
                });
                
                return newResponse;
            }
        } catch (e) {
            responseBody = "[Erro ao ler resposta]";
        }
        
        formatAndPrint("RESPOSTA", {
            url: url,
            statusCode: responseCode,
            headers: responseHeaders,
            response: responseBody
        });
        
        return response;
    };
    
    console.log("[+] OkHttp interceptado com sucesso!");
} catch (e) {
    console.log("[-] OkHttp não encontrado: " + e);
}

// Interceptar HttpURLConnection (Android nativo)
try {
    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    
    HttpURLConnection.getResponseCode.implementation = function() {
        const url = this.getURL().toString();
        const method = this.getRequestMethod();
        
        formatAndPrint("REQUISIÇÃO HttpURLConnection", {
            method: method,
            url: url
        });
        
        const responseCode = this.getResponseCode();
        
        try {
            const inputStream = this.getInputStream();
            const BufferedReader = Java.use("java.io.BufferedReader");
            const InputStreamReader = Java.use("java.io.InputStreamReader");
            const reader = BufferedReader.$new(InputStreamReader.$new(inputStream));
            
            let response = "";
            let line;
            while ((line = reader.readLine()) !== null) {
                response += line + "\n";
            }
            reader.close();
            
            formatAndPrint("RESPOSTA HttpURLConnection", {
                url: url,
                statusCode: responseCode,
                response: response
            });
        } catch (e) {
            console.log("[-] Erro ao ler resposta HttpURLConnection: " + e);
        }
        
        return responseCode;
    };
    
    console.log("[+] HttpURLConnection interceptado com sucesso!");
} catch (e) {
    console.log("[-] HttpURLConnection não encontrado: " + e);
}

// Interceptar Volley (Android)
try {
    const StringRequest = Java.use("com.android.volley.toolbox.StringRequest");
    
    StringRequest.$init.overload('int', 'java.lang.String', 'com.android.volley.Response$Listener', 'com.android.volley.Response$ErrorListener').implementation = function(method, url, listener, errorListener) {
        formatAndPrint("REQUISIÇÃO Volley", {
            method: method === 0 ? "GET" : method === 1 ? "POST" : "OTHER",
            url: url
        });
        
        return this.$init(method, url, listener, errorListener);
    };
    
    console.log("[+] Volley interceptado com sucesso!");
} catch (e) {
    console.log("[-] Volley não encontrado: " + e);
}

// Interceptar Retrofit (Android)
try {
    const ServiceMethod = Java.use("retrofit2.ServiceMethod");
    
    ServiceMethod.invoke.implementation = function(args) {
        try {
            const httpMethod = this.httpMethod.value;
            const relativeUrl = this.relativeUrl.value;
            
            formatAndPrint("REQUISIÇÃO Retrofit", {
                method: httpMethod,
                url: relativeUrl
            });
        } catch (e) {
            console.log("[-] Erro ao interceptar Retrofit: " + e);
        }
        
        return this.invoke(args);
    };
    
    console.log("[+] Retrofit interceptado com sucesso!");
} catch (e) {
    console.log("[-] Retrofit não encontrado: " + e);
}

// Interceptar NSURLSession (iOS)
if (ObjC.available) {
    try {
        const NSURLSession = ObjC.classes.NSURLSession;
        const NSURLRequest = ObjC.classes.NSURLRequest;
        
        // Interceptar dataTaskWithRequest
        const dataTaskWithRequest = NSURLSession["- dataTaskWithRequest:completionHandler:"];
        Interceptor.attach(dataTaskWithRequest.implementation, {
            onEnter: function(args) {
                const request = new ObjC.Object(args[2]);
                const url = request.URL().absoluteString().toString();
                const method = request.HTTPMethod().toString();
                
                formatAndPrint("REQUISIÇÃO iOS NSURLSession", {
                    method: method,
                    url: url
                });
                
                this.url = url;
            },
            onLeave: function(retval) {
                // A resposta será capturada no completion handler
            }
        });
        
        console.log("[+] NSURLSession interceptado com sucesso!");
    } catch (e) {
        console.log("[-] NSURLSession não encontrado: " + e);
    }
    
    // Interceptar AFNetworking (iOS)
    try {
        const AFHTTPSessionManager = ObjC.classes.AFHTTPSessionManager;
        if (AFHTTPSessionManager) {
            const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
            
            methods.forEach(method => {
                try {
                    const methodName = `- ${method.toLowerCase()}:parameters:success:failure:`;
                    const originalMethod = AFHTTPSessionManager[methodName];
                    
                    if (originalMethod) {
                        Interceptor.attach(originalMethod.implementation, {
                            onEnter: function(args) {
                                const url = new ObjC.Object(args[2]).toString();
                                const params = new ObjC.Object(args[3]);
                                
                                formatAndPrint("REQUISIÇÃO iOS AFNetworking", {
                                    method: method,
                                    url: url,
                                    body: params ? params.toString() : ""
                                });
                            }
                        });
                    }
                } catch (e) {
                    // Método não existe, continuar
                }
            });
            
            console.log("[+] AFNetworking interceptado com sucesso!");
        }
    } catch (e) {
        console.log("[-] AFNetworking não encontrado: " + e);
    }
}

// Interceptar fetch API (JavaScript/React Native)
if (typeof global !== 'undefined' && global.fetch) {
    const originalFetch = global.fetch;
    
    global.fetch = function(url, options) {
        const method = options && options.method ? options.method : 'GET';
        const headers = options && options.headers ? options.headers : {};
        const body = options && options.body ? options.body : '';
        
        formatAndPrint("REQUISIÇÃO Fetch API", {
            method: method,
            url: url.toString(),
            headers: headers,
            body: body
        });
        
        return originalFetch.apply(this, arguments).then(response => {
            const clonedResponse = response.clone();
            
            clonedResponse.text().then(text => {
                formatAndPrint("RESPOSTA Fetch API", {
                    url: url.toString(),
                    statusCode: response.status,
                    response: text
                });
            }).catch(e => {
                console.log("[-] Erro ao ler resposta Fetch: " + e);
            });
            
            return response;
        });
    };
    
    console.log("[+] Fetch API interceptado com sucesso!");
}

// Interceptar XMLHttpRequest
if (typeof global !== 'undefined' && global.XMLHttpRequest) {
    const originalXHR = global.XMLHttpRequest;
    
    global.XMLHttpRequest = function() {
        const xhr = new originalXHR();
        
        const originalOpen = xhr.open;
        const originalSend = xhr.send;
        
        xhr.open = function(method, url, async, user, password) {
            this._method = method;
            this._url = url;
            return originalOpen.apply(this, arguments);
        };
        
        xhr.send = function(data) {
            formatAndPrint("REQUISIÇÃO XMLHttpRequest", {
                method: this._method,
                url: this._url,
                body: data
            });
            
            const originalOnReadyStateChange = this.onreadystatechange;
            this.onreadystatechange = function() {
                if (this.readyState === 4) {
                    formatAndPrint("RESPOSTA XMLHttpRequest", {
                        url: this._url,
                        statusCode: this.status,
                        response: this.responseText
                    });
                }
                
                if (originalOnReadyStateChange) {
                    return originalOnReadyStateChange.apply(this, arguments);
                }
            };
            
            return originalSend.apply(this, arguments);
        };
        
        return xhr;
    };
    
    console.log("[+] XMLHttpRequest interceptado com sucesso!");
}

console.log("[*] Interceptador de requisições HTTP ativo!");
console.log("[*] Aguardando requisições...");