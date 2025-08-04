/**
 * Interceptador HTTP Universal
 * Usa hooks de baixo nível para capturar TODO tráfego de rede
 */

console.log("[*] Interceptador Universal iniciado...");

function logTraffic(type, data) {
    console.log(`\n[${"*".repeat(60)}]`);
    console.log(`[${type}] ${new Date().toISOString()}`);
    console.log(`[${"*".repeat(60)}]`);
    console.log(data);
    console.log(`[${"*".repeat(60)}]\n`);
}

Java.perform(function() {
    
    // Hook 1: SSL/TLS - Interceptar dados antes da criptografia
    try {
        const SSLSocketImpl = Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket");
        
        SSLSocketImpl.write.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
            try {
                const data = Java.array('byte', buffer);
                const bytes = [];
                for (let i = offset; i < offset + length && i < data.length; i++) {
                    bytes.push(data[i] & 0xFF);
                }
                const str = String.fromCharCode.apply(null, bytes);
                
                if (str.includes("HTTP") || str.includes("POST") || str.includes("GET") || 
                    str.includes("discord") || str.includes("api")) {
                    logTraffic("SSL_WRITE", str);
                }
            } catch (e) {}
            
            return this.write(buffer, offset, length);
        };
        
        console.log("[+] SSL Socket Write interceptado!");
    } catch (e) {
        console.log("[-] SSL Socket Write falhou: " + e);
    }
    
    // Hook 2: Interceptar todos os OutputStreams
    try {
        const BufferedOutputStream = Java.use("java.io.BufferedOutputStream");
        
        BufferedOutputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, off, len) {
            try {
                const data = Java.array('byte', buffer);
                const bytes = [];
                for (let i = off; i < off + len && i < data.length; i++) {
                    bytes.push(data[i] & 0xFF);
                }
                
                // Tentar decodificar como string
                let str = "";
                for (let i = 0; i < bytes.length; i++) {
                    if (bytes[i] >= 32 && bytes[i] <= 126) {
                        str += String.fromCharCode(bytes[i]);
                    } else {
                        str += ".";
                    }
                }
                
                if (str.includes("discord") || str.includes("api") || str.includes("HTTP") ||
                    str.includes("POST") || str.includes("GET") || str.includes("User-Agent")) {
                    logTraffic("BUFFERED_OUTPUT", str);
                }
            } catch (e) {}
            
            return this.write(buffer, off, len);
        };
        
        console.log("[+] BufferedOutputStream interceptado!");
    } catch (e) {
        console.log("[-] BufferedOutputStream falhou: " + e);
    }
    
    // Hook 3: Interceptar chamadas de sistema de rede
    try {
        const InetAddress = Java.use("java.net.InetAddress");
        
        InetAddress.getByName.implementation = function(hostname) {
            console.log(`[DNS] Resolvendo: ${hostname}`);
            if (hostname.includes("discord") || hostname.includes("gateway")) {
                console.log(`[DISCORD_DNS] ${hostname}`);
            }
            return this.getByName(hostname);
        };
        
        console.log("[+] DNS interceptado!");
    } catch (e) {
        console.log("[-] DNS falhou: " + e);
    }
    
    // Hook 4: Interceptar criação de conexões
    try {
        const SocketChannel = Java.use("java.nio.channels.SocketChannel");
        
        SocketChannel.connect.implementation = function(remote) {
            console.log(`[SOCKET_CHANNEL] Conectando a: ${remote.toString()}`);
            return this.connect(remote);
        };
        
        console.log("[+] SocketChannel interceptado!");
    } catch (e) {
        console.log("[-] SocketChannel falhou: " + e);
    }
    
    // Hook 5: Interceptar ByteBuffer (usado para dados de rede)
    try {
        const ByteBuffer = Java.use("java.nio.ByteBuffer");
        
        ByteBuffer.put.overload('[B').implementation = function(src) {
            try {
                const data = Java.array('byte', src);
                let str = "";
                for (let i = 0; i < Math.min(data.length, 200); i++) {
                    const byte = data[i] & 0xFF;
                    if (byte >= 32 && byte <= 126) {
                        str += String.fromCharCode(byte);
                    } else {
                        str += ".";
                    }
                }
                
                if (str.includes("discord") || str.includes("HTTP") || str.includes("api")) {
                    logTraffic("BYTE_BUFFER", str);
                }
            } catch (e) {}
            
            return this.put(src);
        };
        
        console.log("[+] ByteBuffer interceptado!");
    } catch (e) {
        console.log("[-] ByteBuffer falhou: " + e);
    }
    
    // Hook 6: Interceptar todas as classes que contêm "Call" no nome
    setTimeout(function() {
        console.log("[*] Procurando classes Call...");
        
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.includes("Call") && !className.includes("Callback")) {
                    console.log(`[CALL_CLASS] ${className}`);
                    
                    try {
                        const clazz = Java.use(className);
                        
                        // Tentar interceptar método execute
                        if (clazz.execute) {
                            clazz.execute.implementation = function() {
                                console.log(`[EXECUTE] ${className}.execute() chamado`);
                                
                                // Tentar extrair informações
                                try {
                                    if (this.request) {
                                        const req = this.request();
                                        if (req.url) {
                                            console.log(`[URL] ${req.url().toString()}`);
                                        }
                                    }
                                } catch (e) {}
                                
                                return this.execute();
                            };
                            console.log(`[+] Hook em ${className}.execute`);
                        }
                        
                        // Tentar interceptar método enqueue
                        if (clazz.enqueue) {
                            clazz.enqueue.implementation = function(callback) {
                                console.log(`[ENQUEUE] ${className}.enqueue() chamado`);
                                return this.enqueue(callback);
                            };
                            console.log(`[+] Hook em ${className}.enqueue`);
                        }
                        
                    } catch (e) {
                        // Não conseguiu interceptar
                    }
                }
            },
            onComplete: function() {
                console.log("[*] Busca por classes Call concluída");
            }
        });
    }, 1000);
    
    // Hook 7: Interceptar métodos nativos (JNI)
    try {
        const Runtime = Java.use("java.lang.Runtime");
        
        Runtime.loadLibrary.implementation = function(libname) {
            console.log(`[JNI] Carregando biblioteca: ${libname}`);
            
            // Depois de carregar, tentar interceptar funções nativas
            if (libname.includes("http") || libname.includes("curl") || libname.includes("ssl")) {
                console.log(`[+] Biblioteca de rede detectada: ${libname}`);
            }
            
            return this.loadLibrary(libname);
        };
        
        console.log("[+] Runtime.loadLibrary interceptado!");
    } catch (e) {
        console.log("[-] Runtime.loadLibrary falhou: " + e);
    }
    
    // Hook 8: Interceptar StringBuilder/StringBuffer (para URLs construídas dinamicamente)
    try {
        const StringBuilder = Java.use("java.lang.StringBuilder");
        
        StringBuilder.toString.implementation = function() {
            const result = this.toString();
            
            if (result.includes("http") || result.includes("discord") || result.includes("api")) {
                console.log(`[STRING_BUILD] URL construída: ${result}`);
            }
            
            return result;
        };
        
        console.log("[+] StringBuilder interceptado!");
    } catch (e) {
        console.log("[-] StringBuilder falhou: " + e);
    }
    
    // Hook 9: Monitorar threads de rede
    setTimeout(function() {
        console.log("[*] Monitorando threads ativas...");
        
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.includes("Thread") || className.includes("Executor") || 
                    className.includes("AsyncTask")) {
                    
                    try {
                        const clazz = Java.use(className);
                        
                        if (clazz.run) {
                            clazz.run.implementation = function() {
                                const threadName = Java.use("java.lang.Thread").currentThread().getName();
                                if (threadName.includes("http") || threadName.includes("network") || 
                                    threadName.includes("okhttp") || threadName.includes("discord")) {
                                    console.log(`[THREAD] Thread de rede ativa: ${threadName}`);
                                }
                                return this.run();
                            };
                        }
                    } catch (e) {
                        // Não conseguiu interceptar
                    }
                }
            },
            onComplete: function() {
                console.log("[*] Monitoramento de threads configurado");
            }
        });
    }, 2000);
    
    console.log("[*] Interceptador Universal configurado!");
    console.log("[*] Agora faça algumas ações no Discord para ver o tráfego...");
});