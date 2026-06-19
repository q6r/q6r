/**
 * Script Frida Avançado para OkHttp
 * Múltiplas estratégias para detectar e interceptar OkHttp
 */

console.log("[*] Iniciando interceptador OkHttp avançado...");

// Função para log formatado
function logHttp(type, data) {
    console.log(`\n[${"=".repeat(60)}]`);
    console.log(`[${type}] ${new Date().toISOString()}`);
    console.log(`[${"=".repeat(60)}]`);
    
    if (data.method) console.log(`Método: ${data.method}`);
    if (data.url) console.log(`URL: ${data.url}`);
    if (data.headers) {
        console.log("Headers:");
        Object.keys(data.headers).forEach(key => {
            console.log(`  ${key}: ${data.headers[key]}`);
        });
    }
    if (data.body) console.log(`Body: ${data.body}`);
    if (data.response) {
        const resp = data.response.length > 500 ? data.response.substring(0, 500) + "..." : data.response;
        console.log(`Resposta: ${resp}`);
    }
    if (data.statusCode) console.log(`Status: ${data.statusCode}`);
}

Java.perform(function() {
    console.log("[*] Tentando múltiplas estratégias para OkHttp...");
    
    // Estratégia 1: OkHttp 3.x - RealCall.execute()
    try {
        const RealCall = Java.use("okhttp3.RealCall");
        console.log("[+] Encontrou okhttp3.RealCall");
        
        RealCall.execute.implementation = function() {
            try {
                const request = this.request();
                const url = request.url().toString();
                const method = request.method();
                
                const headers = {};
                const headerNames = request.headers().names();
                const iterator = headerNames.iterator();
                while (iterator.hasNext()) {
                    const name = iterator.next();
                    headers[name] = request.headers().get(name);
                }
                
                let body = "";
                const requestBody = request.body();
                if (requestBody) {
                    try {
                        const buffer = Java.use("okio.Buffer").$new();
                        requestBody.writeTo(buffer);
                        body = buffer.readUtf8();
                    } catch (e) {
                        body = "[Erro ao ler body]";
                    }
                }
                
                logHttp("REQUISIÇÃO OkHttp3", {
                    method: method,
                    url: url,
                    headers: headers,
                    body: body
                });
                
                const response = this.execute();
                const responseCode = response.code();
                
                let responseBody = "";
                try {
                    const respBody = response.body();
                    if (respBody) {
                        responseBody = respBody.string();
                        const ResponseBody = Java.use("okhttp3.ResponseBody");
                        const newBody = ResponseBody.create(respBody.contentType(), responseBody);
                        const newResponse = response.newBuilder().body(newBody).build();
                        
                        logHttp("RESPOSTA OkHttp3", {
                            url: url,
                            statusCode: responseCode,
                            response: responseBody
                        });
                        
                        return newResponse;
                    }
                } catch (e) {
                    console.log("[-] Erro ao ler resposta: " + e);
                }
                
                logHttp("RESPOSTA OkHttp3", {
                    url: url,
                    statusCode: responseCode,
                    response: responseBody
                });
                
                return response;
            } catch (e) {
                console.log("[-] Erro no RealCall.execute: " + e);
                return this.execute();
            }
        };
        
        console.log("[+] OkHttp3 RealCall.execute interceptado!");
    } catch (e) {
        console.log("[-] okhttp3.RealCall não encontrado: " + e);
    }
    
    // Estratégia 2: OkHttp 3.x - RealCall.enqueue() (requisições assíncronas)
    try {
        const RealCall = Java.use("okhttp3.RealCall");
        
        RealCall.enqueue.implementation = function(callback) {
            try {
                const request = this.request();
                const url = request.url().toString();
                const method = request.method();
                
                logHttp("REQUISIÇÃO OkHttp3 Async", {
                    method: method,
                    url: url
                });
                
                // Wrapper do callback para interceptar resposta
                const CallbackWrapper = Java.registerClass({
                    name: "com.frida.CallbackWrapper",
                    implements: [Java.use("okhttp3.Callback")],
                    methods: {
                        onResponse: function(call, response) {
                            try {
                                const responseCode = response.code();
                                let responseBody = "";
                                
                                try {
                                    const respBody = response.body();
                                    if (respBody) {
                                        responseBody = respBody.string();
                                        const ResponseBody = Java.use("okhttp3.ResponseBody");
                                        const newBody = ResponseBody.create(respBody.contentType(), responseBody);
                                        const newResponse = response.newBuilder().body(newBody).build();
                                        
                                        logHttp("RESPOSTA OkHttp3 Async", {
                                            url: url,
                                            statusCode: responseCode,
                                            response: responseBody
                                        });
                                        
                                        callback.onResponse(call, newResponse);
                                        return;
                                    }
                                } catch (e) {
                                    console.log("[-] Erro ao processar resposta async: " + e);
                                }
                                
                                callback.onResponse(call, response);
                            } catch (e) {
                                console.log("[-] Erro no callback onResponse: " + e);
                                callback.onResponse(call, response);
                            }
                        },
                        onFailure: function(call, e) {
                            console.log(`[-] Requisição falhou: ${url} - ${e}`);
                            callback.onFailure(call, e);
                        }
                    }
                });
                
                const wrappedCallback = CallbackWrapper.$new();
                return this.enqueue(wrappedCallback);
            } catch (e) {
                console.log("[-] Erro no RealCall.enqueue: " + e);
                return this.enqueue(callback);
            }
        };
        
        console.log("[+] OkHttp3 RealCall.enqueue interceptado!");
    } catch (e) {
        console.log("[-] Não foi possível interceptar RealCall.enqueue: " + e);
    }
    
    // Estratégia 3: OkHttp 2.x (versão antiga)
    try {
        const Call = Java.use("com.squareup.okhttp.Call");
        console.log("[+] Encontrou OkHttp 2.x");
        
        Call.execute.implementation = function() {
            try {
                const request = this.request();
                const url = request.url().toString();
                const method = request.method();
                
                logHttp("REQUISIÇÃO OkHttp2", {
                    method: method,
                    url: url
                });
                
                const response = this.execute();
                const responseCode = response.code();
                
                logHttp("RESPOSTA OkHttp2", {
                    url: url,
                    statusCode: responseCode
                });
                
                return response;
            } catch (e) {
                console.log("[-] Erro no OkHttp2: " + e);
                return this.execute();
            }
        };
        
        console.log("[+] OkHttp2 interceptado!");
    } catch (e) {
        console.log("[-] OkHttp2 não encontrado: " + e);
    }
    
    // Estratégia 4: Interceptar OkHttpClient.newCall()
    try {
        const OkHttpClient = Java.use("okhttp3.OkHttpClient");
        
        OkHttpClient.newCall.implementation = function(request) {
            try {
                const url = request.url().toString();
                const method = request.method();
                
                console.log(`[+] OkHttpClient.newCall: ${method} ${url}`);
                
                return this.newCall(request);
            } catch (e) {
                console.log("[-] Erro no OkHttpClient.newCall: " + e);
                return this.newCall(request);
            }
        };
        
        console.log("[+] OkHttpClient.newCall interceptado!");
    } catch (e) {
        console.log("[-] OkHttpClient.newCall não encontrado: " + e);
    }
    
    // Estratégia 5: Listar todas as classes carregadas que contêm "okhttp"
    console.log("[*] Procurando classes OkHttp carregadas...");
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.toLowerCase().includes("okhttp")) {
                console.log(`[+] Classe OkHttp encontrada: ${className}`);
            }
        },
        onComplete: function() {
            console.log("[*] Busca por classes OkHttp concluída");
        }
    });
    
    // Estratégia 6: Interceptar HttpURLConnection como fallback
    try {
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        HttpURLConnection.getResponseCode.implementation = function() {
            try {
                const url = this.getURL().toString();
                const method = this.getRequestMethod();
                
                logHttp("REQUISIÇÃO HttpURLConnection", {
                    method: method,
                    url: url
                });
                
                const responseCode = this.getResponseCode();
                
                logHttp("RESPOSTA HttpURLConnection", {
                    url: url,
                    statusCode: responseCode
                });
                
                return responseCode;
            } catch (e) {
                console.log("[-] Erro no HttpURLConnection: " + e);
                return this.getResponseCode();
            }
        };
        
        console.log("[+] HttpURLConnection interceptado como fallback!");
    } catch (e) {
        console.log("[-] HttpURLConnection não encontrado: " + e);
    }
    
    // Estratégia 7: Monitorar carregamento de novas classes
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                Java.classFactory.loader = loader;
                
                // Tentar encontrar OkHttp com este classloader
                try {
                    const RealCall = Java.use("okhttp3.RealCall");
                    console.log(`[+] OkHttp encontrado com classloader: ${loader}`);
                } catch (e) {
                    // Não encontrou com este loader
                }
            } catch (e) {
                // Erro ao tentar usar este classloader
            }
        },
        onComplete: function() {
            console.log("[*] Verificação de classloaders concluída");
        }
    });
    
    console.log("[*] Todas as estratégias de interceptação foram configuradas!");
    console.log("[*] Aguardando requisições HTTP...");
});