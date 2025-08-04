# Interceptador de Requisições HTTP com Frida

Este repositório contém scripts Frida para interceptar e monitorar todas as requisições HTTP feitas por aplicativos móveis (Android e iOS).

## Scripts Disponíveis

### 1. `http_interceptor.js` - Script Completo
- **Descrição**: Script abrangente que intercepta múltiplas bibliotecas de rede
- **Suporte**: 
  - Android: OkHttp, HttpURLConnection, Volley, Retrofit
  - iOS: NSURLSession, AFNetworking
  - JavaScript: Fetch API, XMLHttpRequest
- **Uso**: Ideal para análise completa de tráfego

### 2. `simple_http_interceptor.js` - Script Simplificado
- **Descrição**: Versão mais leve focada nas bibliotecas mais comuns
- **Suporte**: OkHttp (Android) e Fetch API (JavaScript/React Native)
- **Uso**: Ideal para casos simples ou quando o script completo causa problemas

### 3. `discord_http_interceptor.js` - Script Específico para Discord
- **Descrição**: Script otimizado para interceptar tráfego do Discord
- **Suporte**: Múltiplas técnicas de baixo nível (Socket, OutputStream, etc.)
- **Uso**: Quando o Discord não usa bibliotecas padrão

### 4. `universal_http_interceptor.js` - Interceptador Universal
- **Descrição**: Usa hooks de baixo nível em SSL/TLS e sockets
- **Suporte**: Captura TODO tráfego de rede independente da biblioteca
- **Uso**: Para apps que usam bibliotecas customizadas ou ofuscadas

### 5. `discord_diagnostics.js` - Diagnóstico Completo
- **Descrição**: Analisa e descobre todas as bibliotecas de rede usadas
- **Suporte**: Análise completa de classes, métodos e bibliotecas
- **Uso**: Para descobrir como o app funciona antes de interceptar

## Como Usar

### Pré-requisitos
1. **Frida instalado**: `pip install frida-tools`
2. **Dispositivo preparado**:
   - Android: Root ou emulador
   - iOS: Jailbreak

### Comandos Básicos

#### Para Android
```bash
# Listar aplicativos instalados
frida-ps -Ua

# Anexar ao aplicativo em execução
frida -U -l http_interceptor.js "Nome do App"

# Anexar ao aplicativo por package name
frida -U -l http_interceptor.js com.exemplo.app

# Spawn (iniciar) o aplicativo com o script
frida -U -f com.exemplo.app -l http_interceptor.js --no-pause
```

#### Para iOS
```bash
# Listar aplicativos
frida-ps -Ua

# Anexar ao aplicativo
frida -U -l http_interceptor.js "App Name"

# Por bundle identifier
frida -U -l http_interceptor.js com.empresa.app
```

#### Scripts Específicos
```bash
# Script simples
frida -U -l simple_http_interceptor.js "Nome do App"

# Para Discord especificamente
frida -U -f com.discord -l discord_diagnostics.js --no-pause

# Interceptador universal (funciona com qualquer app)
frida -U -l universal_http_interceptor.js com.exemplo.app

# Diagnóstico completo (descobre bibliotecas usadas)
frida -U -l discord_diagnostics.js com.discord
```

## Saída do Script

O script mostra informações detalhadas sobre cada requisição:

```
================================================================================
[REQUISIÇÃO] 2024-01-15T10:30:45.123Z
================================================================================
Método: POST
URL: https://api.exemplo.com/login
Headers:
  Content-Type: application/json
  Authorization: Bearer abc123
Body:
{"username": "user", "password": "pass"}
================================================================================

================================================================================
[RESPOSTA] 2024-01-15T10:30:45.456Z
================================================================================
URL: https://api.exemplo.com/login
Status Code: 200
Headers:
  Content-Type: application/json
Resposta:
{"token": "xyz789", "user_id": 123}
================================================================================
```

## Bibliotecas Interceptadas

### Android
- **OkHttp**: Biblioteca HTTP mais popular para Android
- **HttpURLConnection**: Cliente HTTP nativo do Android
- **Volley**: Biblioteca de rede do Google
- **Retrofit**: Cliente REST type-safe

### iOS
- **NSURLSession**: API nativa de rede do iOS
- **AFNetworking**: Biblioteca de rede popular para iOS

### JavaScript/React Native
- **Fetch API**: API moderna para requisições HTTP
- **XMLHttpRequest**: API tradicional para AJAX

## Solução de Problemas

### Script não funciona
1. Verifique se o app usa uma das bibliotecas suportadas
2. Tente o script simplificado primeiro
3. Verifique se o Frida está atualizado

### App trava ao usar o script
1. Use o `simple_http_interceptor.js`
2. Remova interceptadores específicos que causam problemas
3. Teste em um emulador primeiro

### Não vê requisições HTTPS
- Requisições HTTPS são interceptadas normalmente
- O script captura dados antes da criptografia/depois da descriptografia

### Respostas muito grandes
- O script limita respostas grandes automaticamente
- Ajuste o limite no código se necessário

## Personalização

### Filtrar URLs específicas
```javascript
// Adicione esta condição antes de formatAndPrint
if (url.includes("exemplo.com")) {
    formatAndPrint("REQUISIÇÃO", {
        method: method,
        url: url,
        headers: headers,
        body: requestBody
    });
}
```

### Salvar em arquivo
```javascript
// Adicione no início do script
const fs = require('fs');
const logFile = '/tmp/http_log.txt';

// Modifique a função formatAndPrint para incluir:
fs.appendFileSync(logFile, logData + '\n');
```

### Interceptar apenas métodos específicos
```javascript
// Filtre por método HTTP
if (method === "POST" || method === "PUT") {
    // Só intercepta POST e PUT
}
```

## Dicas Avançadas

1. **Use com Charles Proxy**: Combine com proxy para análise visual
2. **Salve logs**: Redirecione saída para arquivo com `> log.txt`
3. **Filtre ruído**: Ignore requisições de analytics/ads
4. **Teste gradualmente**: Comece com script simples, depois use o completo

## Exemplos de Uso

### Análise de API
```bash
frida -U -l http_interceptor.js com.app.banking > bank_api.log
```

### Debug de React Native
```bash
frida -U -l simple_http_interceptor.js "MyReactApp"
```

### Monitoramento contínuo
```bash
frida -U -l http_interceptor.js com.social.app --no-pause
```

## Limitações

- Não intercepta tráfego de baixo nível (sockets diretos)
- Algumas bibliotecas customizadas podem não ser detectadas
- Apps com proteções anti-Frida podem detectar o script
- Certificados SSL pinning pode bloquear análise de HTTPS

## Contribuindo

Sinta-se livre para:
- Adicionar suporte para novas bibliotecas
- Melhorar a formatação da saída
- Corrigir bugs ou adicionar recursos
- Compartilhar casos de uso interessantes