/**
 * Script de Diagnóstico para Discord
 * Descobre todas as bibliotecas de rede e métodos usados
 */

console.log("[*] Diagnóstico Discord iniciado...");

Java.perform(function() {
    
    console.log("[*] === ANÁLISE COMPLETA DO DISCORD ===");
    
    // 1. Listar TODAS as classes carregadas
    let allClasses = [];
    let httpRelated = [];
    let networkRelated = [];
    let discordClasses = [];
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            allClasses.push(className);
            
            const lower = className.toLowerCase();
            
            // Classes relacionadas a HTTP
            if (lower.includes("http") || lower.includes("okhttp") || 
                lower.includes("retrofit") || lower.includes("volley") ||
                lower.includes("apache") || lower.includes("urlconnection")) {
                httpRelated.push(className);
            }
            
            // Classes relacionadas a rede
            if (lower.includes("network") || lower.includes("socket") || 
                lower.includes("connection") || lower.includes("client") ||
                lower.includes("request") || lower.includes("response") ||
                lower.includes("call") || lower.includes("interceptor")) {
                networkRelated.push(className);
            }
            
            // Classes específicas do Discord
            if (lower.includes("discord") || className.startsWith("com.discord")) {
                discordClasses.push(className);
            }
        },
        onComplete: function() {
            console.log(`\n[ESTATÍSTICAS]`);
            console.log(`Total de classes: ${allClasses.length}`);
            console.log(`Classes HTTP: ${httpRelated.length}`);
            console.log(`Classes Network: ${networkRelated.length}`);
            console.log(`Classes Discord: ${discordClasses.length}`);
            
            console.log(`\n[CLASSES HTTP ENCONTRADAS]`);
            httpRelated.forEach(cls => console.log(`  ${cls}`));
            
            console.log(`\n[CLASSES NETWORK ENCONTRADAS]`);
            networkRelated.slice(0, 20).forEach(cls => console.log(`  ${cls}`));
            if (networkRelated.length > 20) {
                console.log(`  ... e mais ${networkRelated.length - 20} classes`);
            }
            
            console.log(`\n[CLASSES DISCORD ENCONTRADAS]`);
            discordClasses.slice(0, 30).forEach(cls => console.log(`  ${cls}`));
            if (discordClasses.length > 30) {
                console.log(`  ... e mais ${discordClasses.length - 30} classes`);
            }
        }
    });
    
    // 2. Analisar bibliotecas nativas carregadas
    setTimeout(function() {
        console.log(`\n[*] === ANÁLISE DE BIBLIOTECAS NATIVAS ===`);
        
        try {
            const System = Java.use("java.lang.System");
            
            System.loadLibrary.implementation = function(libname) {
                console.log(`[NATIVE_LIB] ${libname}`);
                
                if (libname.includes("http") || libname.includes("curl") || 
                    libname.includes("ssl") || libname.includes("crypto") ||
                    libname.includes("discord")) {
                    console.log(`  [!] BIBLIOTECA DE REDE DETECTADA: ${libname}`);
                }
                
                return this.loadLibrary(libname);
            };
            
            System.load.implementation = function(filename) {
                console.log(`[NATIVE_LOAD] ${filename}`);
                return this.load(filename);
            };
            
        } catch (e) {
            console.log("[-] Não foi possível interceptar bibliotecas nativas");
        }
    }, 1000);
    
    // 3. Analisar métodos específicos de classes suspeitas
    setTimeout(function() {
        console.log(`\n[*] === ANÁLISE DETALHADA DE MÉTODOS ===`);
        
        // Analisar classes que podem ser de rede
        const suspiciousClasses = [
            "okhttp3.RealCall",
            "okhttp3.OkHttpClient", 
            "retrofit2.Call",
            "com.android.volley.Request",
            "java.net.HttpURLConnection",
            "javax.net.ssl.HttpsURLConnection"
        ];
        
        suspiciousClasses.forEach(className => {
            try {
                const clazz = Java.use(className);
                console.log(`\n[CLASSE] ${className}`);
                
                const methods = clazz.class.getDeclaredMethods();
                console.log(`  Métodos encontrados: ${methods.length}`);
                
                for (let i = 0; i < Math.min(methods.length, 10); i++) {
                    const method = methods[i];
                    console.log(`    ${method.getName()}`);
                }
                
                if (methods.length > 10) {
                    console.log(`    ... e mais ${methods.length - 10} métodos`);
                }
                
            } catch (e) {
                console.log(`[CLASSE] ${className} - NÃO ENCONTRADA`);
            }
        });
        
    }, 2000);
    
    // 4. Procurar por padrões específicos do Discord
    setTimeout(function() {
        console.log(`\n[*] === ANÁLISE ESPECÍFICA DO DISCORD ===`);
        
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.includes("discord") || className.includes("Discord")) {
                    try {
                        const clazz = Java.use(className);
                        const methods = clazz.class.getDeclaredMethods();
                        
                        console.log(`\n[DISCORD_CLASS] ${className}`);
                        
                        for (let i = 0; i < methods.length; i++) {
                            const methodName = methods[i].getName();
                            
                            // Procurar métodos relacionados a rede
                            if (methodName.includes("request") || methodName.includes("send") ||
                                methodName.includes("post") || methodName.includes("get") ||
                                methodName.includes("fetch") || methodName.includes("call") ||
                                methodName.includes("execute") || methodName.includes("connect")) {
                                
                                console.log(`  [NETWORK_METHOD] ${methodName}`);
                                
                                // Tentar interceptar este método
                                try {
                                    const originalMethod = clazz[methodName];
                                    if (originalMethod) {
                                        clazz[methodName].implementation = function() {
                                            console.log(`[DISCORD_HOOK] ${className}.${methodName}() chamado`);
                                            
                                            // Tentar capturar argumentos
                                            for (let j = 0; j < arguments.length; j++) {
                                                try {
                                                    const arg = arguments[j];
                                                    if (arg && typeof arg.toString === 'function') {
                                                        const argStr = arg.toString();
                                                        if (argStr.includes("http") || argStr.includes("discord") || 
                                                            argStr.includes("api") || argStr.includes("gateway")) {
                                                            console.log(`    [ARG${j}] ${argStr}`);
                                                        }
                                                    }
                                                } catch (e) {}
                                            }
                                            
                                            return originalMethod.apply(this, arguments);
                                        };
                                        
                                        console.log(`    [HOOKED] ${methodName}`);
                                    }
                                } catch (e) {
                                    console.log(`    [HOOK_FAILED] ${methodName}: ${e}`);
                                }
                            }
                        }
                        
                    } catch (e) {
                        console.log(`[DISCORD_CLASS_ERROR] ${className}: ${e}`);
                    }
                }
            },
            onComplete: function() {
                console.log(`\n[*] Análise específica do Discord concluída`);
            }
        });
        
    }, 3000);
    
    // 5. Interceptar construção de URLs
    setTimeout(function() {
        console.log(`\n[*] === INTERCEPTANDO CONSTRUÇÃO DE URLS ===`);
        
        try {
            const URL = Java.use("java.net.URL");
            
            URL.$init.overload('java.lang.String').implementation = function(spec) {
                if (spec.includes("discord") || spec.includes("gateway") || spec.includes("api")) {
                    console.log(`[URL_CREATED] ${spec}`);
                }
                return this.$init(spec);
            };
            
            console.log("[+] Interceptação de URLs configurada");
        } catch (e) {
            console.log("[-] Falha ao interceptar URLs: " + e);
        }
        
    }, 4000);
    
    // 6. Monitorar threads em tempo real
    setTimeout(function() {
        console.log(`\n[*] === MONITORAMENTO DE THREADS ===`);
        
        setInterval(function() {
            try {
                const Thread = Java.use("java.lang.Thread");
                const currentThread = Thread.currentThread();
                const threadName = currentThread.getName();
                
                if (threadName.includes("http") || threadName.includes("network") || 
                    threadName.includes("okhttp") || threadName.includes("discord") ||
                    threadName.includes("retrofit") || threadName.includes("volley")) {
                    console.log(`[ACTIVE_THREAD] ${threadName}`);
                }
            } catch (e) {}
        }, 5000);
        
    }, 5000);
    
    console.log(`\n[*] === DIAGNÓSTICO CONFIGURADO ===`);
    console.log(`[*] Agora use o Discord e observe os logs...`);
    console.log(`[*] Envie uma mensagem, entre em um canal, etc.`);
});