/**
 * Script Frida Específico para Discord
 * Detecta e intercepta todas as bibliotecas de rede possíveis
 */

console.log("[*] Interceptador Discord iniciado...");

function logRequest(type, method, url, data) {
    console.log(`\n[${"=".repeat(50)}]`);
    console.log(`[${type}] ${method || "?"} ${url || "?"}`);
    if (data) console.log(`Data: ${data.substring(0, 300)}${data.length > 300 ? "..." : ""}`);
    console.log(`[${"=".repeat(50)}]`);
}

Java.perform(function() {
    console.log("[*] Analisando classes carregadas...");
    
    // Primeiro, vamos descobrir que bibliotecas o Discord usa
    let httpClasses = [];
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            const lower = className.toLowerCase();
            if (lower.includes("http") || lower.includes("okhttp") || 
                lower.includes("retrofit") || lower.includes("volley") ||
                lower.includes("request") || lower.includes("client") ||
                lower.includes("network") || lower.includes("connection")) {
                httpClasses.push(className);
            }
        },
        onComplete: function() {
            console.log(`[+] Encontradas ${httpClasses.length} classes relacionadas a rede:`);
            httpClasses.forEach(cls => console.log(`    ${cls}`));
        }
    });
    
    // Estratégia 1: Socket de baixo nível
    try {
        const Socket = Java.use("java.net.Socket");
        const SocketConnect = Socket.connect.overload('java.net.SocketAddress', 'int');
        
        SocketConnect.implementation = function(endpoint, timeout) {
            try {
                console.log(`[SOCKET] Conectando a: ${endpoint.toString()}`);
            } catch (e) {}
            return this.connect(endpoint, timeout);
        };
        
        console.log("[+] Socket interceptado!");
    } catch (e) {
        console.log("[-] Socket não interceptado: " + e);
    }
    
    // Estratégia 2: OutputStream (captura dados enviados)
    try {
        const OutputStream = Java.use("java.io.OutputStream");
        
        OutputStream.write.overload('[B').implementation = function(bytes) {
            try {
                const data = Java.use("java.lang.String").$new(bytes);
                if (data.includes("HTTP") || data.includes("POST") || data.includes("GET")) {
                    logRequest("OUTPUT_STREAM", "?", "?", data);
                }
            } catch (e) {}
            return this.write(bytes);
        };
        
        console.log("[+] OutputStream interceptado!");
    } catch (e) {
        console.log("[-] OutputStream não interceptado: " + e);
    }
    
    // Estratégia 3: HttpURLConnection (nativo Android)
    try {
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        HttpURLConnection.setRequestMethod.implementation = function(method) {
            this._fridaMethod = method;
            return this.setRequestMethod(method);
        };
        
        HttpURLConnection.getResponseCode.implementation = function() {
            try {
                const url = this.getURL().toString();
                const method = this._fridaMethod || this.getRequestMethod();
                logRequest("HttpURLConnection", method, url, "");
            } catch (e) {}
            return this.getResponseCode();
        };
        
        console.log("[+] HttpURLConnection interceptado!");
    } catch (e) {
        console.log("[-] HttpURLConnection falhou: " + e);
    }
    
    // Estratégia 4: Procurar por todas as classes que implementam interfaces de rede
    setTimeout(function() {
        console.log("[*] Procurando implementações de Call, Request, Response...");
        
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                try {
                    const clazz = Java.use(className);
                    
                    // Procurar métodos que parecem ser de rede
                    const methods = clazz.class.getDeclaredMethods();
                    for (let i = 0; i < methods.length; i++) {
                        const methodName = methods[i].getName();
                        if (methodName === "execute" || methodName === "enqueue" || 
                            methodName === "newCall" || methodName === "request") {
                            
                            console.log(`[+] Método suspeito encontrado: ${className}.${methodName}`);
                            
                            try {
                                // Tentar interceptar este método
                                clazz[methodName].implementation = function() {
                                    console.log(`[HOOK] ${className}.${methodName} chamado`);
                                    try {
                                        // Tentar extrair informações do objeto
                                        if (this.request && typeof this.request === "function") {
                                            const req = this.request();
                                            if (req.url && typeof req.url === "function") {
                                                const url = req.url().toString();
                                                logRequest("CUSTOM_HOOK", "?", url, "");
                                            }
                                        }
                                    } catch (e) {}
                                    return this[methodName].apply(this, arguments);
                                };
                                console.log(`[+] Hook aplicado em ${className}.${methodName}`);
                            } catch (e) {
                                // Não conseguiu interceptar
                            }
                        }
                    }
                } catch (e) {
                    // Classe não acessível
                }
            },
            onComplete: function() {
                console.log("[*] Análise de métodos concluída");
            }
        });
    }, 2000);
    
    // Estratégia 5: Interceptar System.loadLibrary para ver bibliotecas nativas
    try {
        const System = Java.use("java.lang.System");
        
        System.loadLibrary.implementation = function(libname) {
            console.log(`[LIBRARY] Carregando biblioteca nativa: ${libname}`);
            return this.loadLibrary(libname);
        };
        
        console.log("[+] System.loadLibrary interceptado!");
    } catch (e) {
        console.log("[-] System.loadLibrary falhou: " + e);
    }
    
    // Estratégia 6: Interceptar URL.openConnection()
    try {
        const URL = Java.use("java.net.URL");
        
        URL.openConnection.overload().implementation = function() {
            console.log(`[URL] Abrindo conexão para: ${this.toString()}`);
            return this.openConnection();
        };
        
        console.log("[+] URL.openConnection interceptado!");
    } catch (e) {
        console.log("[-] URL.openConnection falhou: " + e);
    }
    
    // Estratégia 7: Procurar especificamente por classes do Discord
    setTimeout(function() {
        console.log("[*] Procurando classes específicas do Discord...");
        
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.includes("discord") || className.includes("Discord")) {
                    console.log(`[DISCORD] Classe encontrada: ${className}`);
                    
                    try {
                        const clazz = Java.use(className);
                        const methods = clazz.class.getDeclaredMethods();
                        
                        for (let i = 0; i < methods.length; i++) {
                            const methodName = methods[i].getName();
                            if (methodName.includes("request") || methodName.includes("send") ||
                                methodName.includes("post") || methodName.includes("get")) {
                                console.log(`  [+] Método interessante: ${methodName}`);
                            }
                        }
                    } catch (e) {
                        // Não conseguiu analisar a classe
                    }
                }
            },
            onComplete: function() {
                console.log("[*] Análise de classes Discord concluída");
            }
        });
    }, 3000);
    
    // Estratégia 8: Hook em WebView (caso use WebView para requisições)
    try {
        const WebView = Java.use("android.webkit.WebView");
        
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log(`[WEBVIEW] Carregando URL: ${url}`);
            return this.loadUrl(url);
        };
        
        console.log("[+] WebView interceptado!");
    } catch (e) {
        console.log("[-] WebView não encontrado: " + e);
    }
    
    // Estratégia 9: Interceptar JSONObject (para ver dados de API)
    try {
        const JSONObject = Java.use("org.json.JSONObject");
        
        JSONObject.toString.implementation = function() {
            const result = this.toString();
            if (result.length > 50 && (result.includes("token") || result.includes("auth") || 
                result.includes("message") || result.includes("user"))) {
                console.log(`[JSON] Dados: ${result.substring(0, 200)}...`);
            }
            return result;
        };
        
        console.log("[+] JSONObject interceptado!");
    } catch (e) {
        console.log("[-] JSONObject falhou: " + e);
    }
    
    console.log("[*] Todos os hooks configurados! Aguardando atividade de rede...");
});