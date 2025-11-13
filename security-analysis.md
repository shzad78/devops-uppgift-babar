# Säkerhetsanalys - Task Management API

## Sammanfattning

Detta dokument analyserar säkerhetshot för Task Management REST API och definierar säkerhetskrav baserade på OWASP Top 10 2021. Varje hot utvärderas med specifika krav, implementeringsstrategier och testmetoder.

---

## 1. Injektionsattacker

### 1.1 SQL/NoSQL-injektion
**Hotnivå**: 🔴 **KRITISK**

#### Beskrivning
Även om vår applikation använder minneslagring (ingen databas), kan injektionssårbarheter fortfarande förekomma genom:
- Kommandinjektion via användarinput
- Kodinjektion genom eval() eller liknande funktioner
- Server-Side JavaScript Injection om input bearbetas osäkert

#### Nuvarande sårbarheter
- Uppgiftstitlar och beskrivningar lagras utan sanering
- Ingen kodning av specialtecken för input
- Potential för prototype pollution i JavaScript-objekt

#### Säkerhetskrav

| Krav | Beskrivning | Prioritet |
|------|-------------|-----------|
| **KR-INJ-001** | Input-sanering för all användarinput | KRITISK |
| **KR-INJ-002** | Ingen användning av eval() eller Function()-konstruktörer | KRITISK |
| **KR-INJ-003** | Förhindra prototype pollution-attacker | VIKTIG |

#### Implementeringsstrategi

```javascript
// 1. Lägg till input-sanering middleware
const validator = require('validator');

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return validator.escape(input.trim());
}

// 2. Uppdatera validation.js
function validateTask(req, res, next) {
  const { title, description } = req.body;
  
  // Sanera inputs
  if (title) req.body.title = sanitizeInput(title);
  if (description) req.body.description = sanitizeInput(description);
  
  // Förhindra prototype pollution
  if (title.includes('__proto__') || title.includes('constructor')) {
    return res.status(400).json({ error: 'Ogiltig input upptäckt' });
  }
  
  // ... befintlig validering
}

// 3. Frys kritiska objekt
Object.freeze(Object.prototype);
```

#### Testbarhet
```http
### Test: Prototype pollution-försök
POST http://localhost:3000/api/tasks
Authorization: Bearer TOKEN
Content-Type: application/json

{
  "title": "__proto__",
  "description": "skadlig"
}
# Förväntat: 400 Bad Request

### Test: Hantering av specialtecken
POST http://localhost:3000/api/tasks
Authorization: Bearer TOKEN
Content-Type: application/json

{
  "title": "<script>alert('xss')</script>",
  "description": "'; DROP TABLE tasks--"
}
# Förväntat: Sanerad och säkert lagrad
```

---

## 2. Bruten autentisering

### 2.1 Svag autentiseringsmekanism
**Hotnivå**: 🔴 **KRITISK**

#### Beskrivning
Nuvarande sårbarheter:
- Lösenord lagras i klartext i minnet
- Enkel token-generering utan kryptografisk säkerhet
- Ingen token-utgång
- Ingen hastighetsbegränsning för inloggningsförsök
- Inga krav på lösenordskomplexitet
- Sessioner upphör aldrig

#### Säkerhetskrav

| Krav | Beskrivning | Prioritet |
|------|-------------|-----------|
| **KR-AUTH-001** | Hasha lösenord med bcrypt | KRITISK |
| **KR-AUTH-002** | Använd kryptografiskt säkra tokens (JWT) | KRITISK |
| **KR-AUTH-003** | Implementera token-utgång | KRITISK |
| **KR-AUTH-004** | Lägg till hastighetsbegränsning för inloggningsförsök | KRITISK |
| **KR-AUTH-005** | Tvinga stark lösenordspolicy | VIKTIG |
| **KR-AUTH-006** | Implementera kontolåsning efter misslyckade försök | VIKTIG |
| **KR-AUTH-007** | Lägg till refresh token-mekanism | ÖNSKVÄRD |

#### Implementeringsstrategi

```javascript
// 1. Installera beroenden
// npm install bcrypt jsonwebtoken express-rate-limit

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// 2. Uppdatera auth.js
const JWT_SECRET = process.env.JWT_SECRET || 'ändra-denna-hemlighet-i-produktion';
const JWT_EXPIRES_IN = '1h';
const SALT_ROUNDS = 12;

async function register(username, password) {
  // Tvinga lösenordspolicy
  if (password.length < 8) {
    throw new Error('Lösenordet måste vara minst 8 tecken');
  }
  if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
    throw new Error('Lösenordet måste innehålla stor bokstav, liten bokstav och siffra');
  }
  
  if (users.has(username)) {
    throw new Error('Användaren finns redan');
  }
  
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  users.set(username, { username, password: hashedPassword });
  return { username };
}

async function login(username, password) {
  const user = users.get(username);
  if (!user) {
    throw new Error('Ogiltiga inloggningsuppgifter');
  }
  
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    throw new Error('Ogiltiga inloggningsuppgifter');
  }
  
  const token = jwt.sign(
    { username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
  
  return token;
}

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Ingen token tillhandahållen' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.username;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Ogiltig eller utgången token' });
  }
}

// 3. Lägg till hastighetsbegränsning i authRoutes.js
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuter
  max: 5, // 5 försök
  message: 'För många inloggningsförsök, försök igen senare'
});

router.post('/login', loginLimiter, validateAuth, async (req, res, next) => {
  // ... inloggningslogik
});
```

#### Testbarhet
```http
### Test: Avvisning av svagt lösenord
POST http://localhost:3000/api/auth/register
Content-Type: application/json

{
  "username": "test",
  "password": "svagt"
}
# Förväntat: 400 med lösenordskravsfel

### Test: Token-utgång (vänta 1 timme + 1 minut)
GET http://localhost:3000/api/tasks
Authorization: Bearer UTGÅNGEN_TOKEN
# Förväntat: 403 Ogiltig eller utgången token

### Test: Hastighetsbegränsning (skicka 6 gånger snabbt)
POST http://localhost:3000/api/auth/login
Content-Type: application/json

{
  "username": "test",
  "password": "felpass"
}
# Förväntat: 429 Too Many Requests vid 6:e försöket
```

---

## 3. Exponering av känslig data

### 3.1 Dataläckage
**Hotnivå**: 🟠 **VIKTIG**

#### Beskrivning
Nuvarande sårbarheter:
- Felmeddelanden kan exponera interna systemdetaljer
- Ingen HTTPS-tvingande
- Tokens synliga i loggar
- Ingen datakryptering i vila (i minnet)

#### Säkerhetskrav

| Krav | Beskrivning | Prioritet |
|------|-------------|-----------|
| **KR-DATA-001** | Generiska felmeddelanden för produktion | KRITISK |
| **KR-DATA-002** | HTTPS-tvingande | KRITISK |
| **KR-DATA-003** | Sanera loggar för att ta bort känslig data | VIKTIG |
| **KR-DATA-004** | Lägg till säkerhetsheaders | VIKTIG |
| **KR-DATA-005** | Implementera request-loggning med sanering | ÖNSKVÄRD |

#### Implementeringsstrategi

```javascript
// 1. Installera helmet för säkerhetsheaders
// npm install helmet

const helmet = require('helmet');

// 2. Uppdatera server.js
app.use(helmet());

// HTTPS redirect middleware
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

// 3. Förbättra felhantering
app.use((err, req, res, next) => {
  // Logga fullständigt fel server-side
  console.error({
    timestamp: new Date().toISOString(),
    error: err.message,
    stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined
  });
  
  // Skicka generiskt fel till klient i produktion
  const message = process.env.NODE_ENV === 'production' 
    ? 'Ett fel uppstod' 
    : err.message;
    
  res.status(err.status || 500).json({ error: message });
});

// 4. Sanera loggar
function sanitizeForLog(obj) {
  const sanitized = { ...obj };
  if (sanitized.password) sanitized.password = '[DOLD]';
  if (sanitized.token) sanitized.token = '[DOLD]';
  if (sanitized.authorization) sanitized.authorization = '[DOLD]';
  return sanitized;
}
```

#### Testbarhet
```http
### Test: Exponering av felmeddelande
GET http://localhost:3000/api/tasks/99999
Authorization: Bearer OGILTIG_TOKEN
# Förväntat: Generiskt fel i produktion, detaljerat i dev

### Test: Säkerhetsheaders närvarande
GET http://localhost:3000/
# Förväntat: X-Content-Type-Options, X-Frame-Options, etc.
```

---

## 4. Bruten åtkomstkontroll

### 4.1 Horisontell privilegieeskalering
**Hotnivå**: 🔴 **KRITISK**

#### Beskrivning
Nuvarande implementation implementerar korrekt användarisolering:
- ✅ Uppgifter filtreras efter ägare
- ✅ Användare kan bara komma åt sina egna uppgifter
- ⚠️ Ingen rollbaserad åtkomstkontroll (RBAC)
- ⚠️ Ingen revisions-loggning av åtkomstförsök

#### Säkerhetskrav

| Krav | Beskrivning | Prioritet |
|------|-------------|-----------|
| **KR-ACCESS-001** | Bibehåll användarisolering i alla operationer | KRITISK |
| **KR-ACCESS-002** | Lägg till auktoriseringskontroller före affärslogik | KRITISK |
| **KR-ACCESS-003** | Implementera rollbaserad åtkomstkontroll | VIKTIG |
| **KR-ACCESS-004** | Lägg till revisions-loggning för åtkomstförsök | VIKTIG |
| **KR-ACCESS-005** | Implementera resursnivå-behörigheter | ÖNSKVÄRD |

#### Implementeringsstrategi

```javascript
// 1. Lägg till rollsystem
const UserRole = {
  USER: 'användare',
  ADMIN: 'admin'
};

function register(username, password, role = UserRole.USER) {
  // ... befintlig kod
  users.set(username, { 
    username, 
    password: hashedPassword,
    role: role 
  });
}

// 2. Lägg till auktoriserings-middleware
function requireRole(role) {
  return (req, res, next) => {
    const user = users.get(req.user);
    if (!user || user.role !== role) {
      return res.status(403).json({ error: 'Otillräckliga behörigheter' });
    }
    next();
  };
}

// 3. Lägg till revisions-loggning
const auditLog = [];

function logAccess(username, action, resource, result) {
  auditLog.push({
    timestamp: new Date().toISOString(),
    username,
    action,
    resource,
    result,
    ip: '...' // Lägg till från req.ip
  });
}

// 4. Applicera på routes
router.get('/:id', (req, res) => {
  const task = taskService.getTaskById(req.params.id, req.user);
  
  if (!task) {
    logAccess(req.user, 'LÄS', `uppgift:${req.params.id}`, 'NEKAD');
    return res.status(404).json({ error: 'Uppgift hittades inte' });
  }
  
  logAccess(req.user, 'LÄS', `uppgift:${req.params.id}`, 'TILLÅTEN');
  res.json(task);
});
```

#### Testbarhet
```http
### Test: Åtkomstförsök mellan användare
# 1. Skapa uppgift som användare1
POST http://localhost:3000/api/tasks
Authorization: Bearer ANVÄNDARE1_TOKEN
Content-Type: application/json
{"title": "Användare1 uppgift"}

# 2. Försök komma åt som användare2
GET http://localhost:3000/api/tasks/1
Authorization: Bearer ANVÄNDARE2_TOKEN
# Förväntat: 404 Not Found

### Test: Admin-åtkomst till revisionsloggar
GET http://localhost:3000/api/admin/audit
Authorization: Bearer ADMIN_TOKEN
# Förväntat: 200 med revisionsloggdata
```

---

## 5. Säkerhets-felkonfiguration

### 5.1 Osäkra standardinställningar
**Hotnivå**: 🟠 **VIKTIG**

#### Beskrivning
Nuvarande problem:
- Standard JWT-hemlighet är hårdkodad
- Inga miljöspecifika konfigurationer
- CORS inte konfigurerad
- Inga storleksgränser för requests
- Debug-läge aktiverat som standard

#### Säkerhetskrav

| Krav | Beskrivning | Prioritet |
|------|-------------|-----------|
| **KR-CONFIG-001** | Använd miljövariabler för hemligheter | KRITISK |
| **KR-CONFIG-002** | Konfigurera CORS lämpligt | KRITISK |
| **KR-CONFIG-003** | Sätt storleksgränser för requests | VIKTIG |
| **KR-CONFIG-004** | Inaktivera debug-läge i produktion | VIKTIG |
| **KR-CONFIG-005** | Implementera korrekt konfigurationshantering | VIKTIG |

#### Implementeringsstrategi

```javascript
// 1. Skapa .env-fil (lägg till i .gitignore!)
/*
NODE_ENV=production
JWT_SECRET=din-super-hemliga-nyckel-ändra-denna
PORT=3000
CORS_ORIGIN=https://dindomän.se
MAX_REQUEST_SIZE=1mb
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
*/

// 2. Installera dotenv
// npm install dotenv cors

// 3. Uppdatera server.js
require('dotenv').config();
const cors = require('cors');

// Validera obligatoriska miljövariabler
const requiredEnvVars = ['JWT_SECRET'];
requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar]) {
    console.error(`Saknar obligatorisk miljövariabel: ${envVar}`);
    process.exit(1);
  }
});

// Konfigurera CORS
const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  optionsSuccessStatus: 200,
  credentials: true
};
app.use(cors(corsOptions));

// Sätt storleksgräns för request
app.use(express.json({ limit: process.env.MAX_REQUEST_SIZE || '1mb' }));

// Inaktivera x-powered-by header
app.disable('x-powered-by');

// 4. Konfigurationsvalidering
const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  jwtSecret: process.env.JWT_SECRET,
  port: process.env.PORT || 3000,
  isProduction: process.env.NODE_ENV === 'production'
};

if (config.isProduction && config.jwtSecret === 'ändra-denna-hemlighet-i-produktion') {
  throw new Error('Måste sätta JWT_SECRET i produktion!');
}
```

#### Testbarhet
```bash
# Test: Saknad JWT_SECRET
unset JWT_SECRET
npm start
# Förväntat: Fel och avslut

# Test: Storleksgräns för request
curl -X POST http://localhost:3000/api/tasks \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"'$(python3 -c "print('A'*10000000)")'"}'
# Förväntat: 413 Payload Too Large
```

---

## 6. Cross-Site Scripting (XSS)

### 6.1 Lagrad XSS
**Hotnivå**: 🟠 **VIKTIG**

#### Beskrivning
Även om detta är ett API (serverar inte HTML), kan XSS fortfarande förekomma om:
- Data returneras oescapad till frontend-applikationer
- JSON-svar inkluderar osanerad användarinput
- Felmeddelanden reflekterar användarinput

#### Säkerhetskrav

| Krav | Beskrivning | Prioritet |
|------|-------------|-----------|
| **KR-XSS-001** | Sanera all användarinput före lagring | VIKTIG |
| **KR-XSS-002** | Escapa outputs i felmeddelanden | VIKTIG |
| **KR-XSS-003** | Sätt Content-Type headers korrekt | VIKTIG |
| **KR-XSS-004** | Implementera Content Security Policy | ÖNSKVÄRD |

#### Implementeringsstrategi

```javascript
// 1. Output-kodning (redan täckt i injektionssektionen)
// 2. Sätt säkerhetsheaders
app.use((req, res, next) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// 3. CSP-header för API
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'none'"]
  }
}));

// 4. Validera Content-Type på POST/PUT
app.use((req, res, next) => {
  if (['POST', 'PUT'].includes(req.method)) {
    if (!req.is('application/json')) {
      return res.status(415).json({ 
        error: 'Content-Type måste vara application/json' 
      });
    }
  }
  next();
});
```

#### Testbarhet
```http
### Test: XSS i uppgiftstitel
POST http://localhost:3000/api/tasks
Authorization: Bearer TOKEN
Content-Type: application/json

{
  "title": "<img src=x onerror=alert('xss')>",
  "description": "<script>alert('xss')</script>"
}
# Förväntat: Data sanerad före lagring

### Test: Content-Type-tvingande
POST http://localhost:3000/api/tasks
Authorization: Bearer TOKEN
Content-Type: text/plain

title=test
# Förväntat: 415 Unsupported Media Type
```

---

## 7. Otillräcklig loggning & övervakning

### 7.1 Brist på säkerhetsövervakning
**Hotnivå**: 🟡 **VIKTIG**

#### Beskrivning
Nuvarande problem:
- Ingen centraliserad loggning
- Ingen säkerhetshändelseövervakning
- Ingen larm-mekanism
- Ingen request-spårning

#### Säkerhetskrav

| Krav | Beskrivning | Prioritet |
|------|-------------|-----------|
| **KR-LOG-001** | Logga alla autentiseringshändelser | KRITISK |
| **KR-LOG-002** | Logga alla auktoriseringsmisslyckanden | KRITISK |
| **KR-LOG-003** | Implementera request-ID-spårning | VIKTIG |
| **KR-LOG-004** | Sätt upp säkerhetslarm | VIKTIG |
| **KR-LOG-005** | Implementera logg-rotation | ÖNSKVÄRD |

#### Implementeringsstrategi

```javascript
// 1. Installera winston för loggning
// npm install winston uuid

const winston = require('winston');
const { v4: uuidv4 } = require('uuid');

// 2. Konfigurera logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error' 
    }),
    new winston.transports.File({ 
      filename: 'logs/säkerhet.log',
      level: 'warn'
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log' 
    })
  ]
});

// 3. Request-spårning middleware
app.use((req, res, next) => {
  req.id = uuidv4();
  req.startTime = Date.now();
  
  res.on('finish', () => {
    logger.info('Request slutförd', {
      requestId: req.id,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: Date.now() - req.startTime,
      userAgent: req.get('user-agent')
    });
  });
  
  next();
});

// 4. Säkerhetshändelseloggning
function logSecurityEvent(type, details, severity = 'warn') {
  logger.log(severity, 'Säkerhetshändelse', {
    type,
    ...details,
    timestamp: new Date().toISOString()
  });
  
  // Larm vid kritiska händelser
  if (severity === 'error') {
    // Skicka larm (e-post, Slack, PagerDuty, etc.)
    console.error('SÄKERHETSLARM:', type, details);
  }
}

// 5. Applicera på autentisering
async function login(username, password) {
  const user = users.get(username);
  
  if (!user) {
    logSecurityEvent('INLOGGNING_MISSLYCKADES', { 
      username, 
      anledning: 'användare_hittades_inte' 
    });
    throw new Error('Ogiltiga inloggningsuppgifter');
  }
  
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    logSecurityEvent('INLOGGNING_MISSLYCKADES', { 
      username, 
      anledning: 'ogiltigt_lösenord' 
    });
    throw new Error('Ogiltiga inloggningsuppgifter');
  }
  
  logSecurityEvent('INLOGGNING_LYCKADES', { username }, 'info');
  // ... resten av inloggningen
}
```

#### Testbarhet
```bash
# Test: Kontrollera att loggar skapas
ls -la logs/
# Förväntat: error.log, säkerhet.log, combined.log

# Test: Misslyckad inloggning loggad
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"fel"}'

grep "INLOGGNING_MISSLYCKADES" logs/säkerhet.log
# Förväntat: Post med tidsstämpel och detaljer
```

---

## 8. Server-Side Request Forgery (SSRF)

### 8.1 SSRF-förebyggande
**Hotnivå**: 🟢 **ÖNSKVÄRD**

#### Beskrivning
Nuvarande status: Låg risk (inga externa HTTP-requests i nuvarande implementation)
Framtida övervägande om funktioner läggs till:
- Webhook-notifikationer
- Externa API-integrationer
- Filuppladdningar från URLs

#### Säkerhetskrav

| Krav | Beskrivning | Prioritet |
|------|-------------|-----------|
| **KR-SSRF-001** | Validera och vitlista externa URLs | VIKTIG* |
| **KR-SSRF-002** | Inaktivera följande omdirigeringar | VIKTIG* |
| **KR-SSRF-003** | Använd nätverkssegmentering | ÖNSKVÄRD |

*Om externa requests läggs till

---

## Prioritetssammanfattning

### 🔴 KRITISK (Måste implementeras)

1. **Lösenordshashing** (KR-AUTH-001)
2. **JWT med utgång** (KR-AUTH-002, KR-AUTH-003)
3. **Hastighetsbegränsning** (KR-AUTH-004)
4. **Input-sanering** (KR-INJ-001)
5. **HTTPS-tvingande** (KR-DATA-002)
6. **Miljövariabler för hemligheter** (KR-CONFIG-001)
7. **CORS-konfiguration** (KR-CONFIG-002)
8. **Användarisolering** (KR-ACCESS-001, KR-ACCESS-002)
9. **Autentiserings-/Auktoriseringsloggning** (KR-LOG-001, KR-LOG-002)

### 🟠 VIKTIG (Bör implementeras)

1. **Stark lösenordspolicy** (KR-AUTH-005)
2. **Kontolåsning** (KR-AUTH-006)
3. **Förebyggande av prototype pollution** (KR-INJ-003)
4. **Loggsanering** (KR-DATA-003)
5. **Säkerhetsheaders** (KR-DATA-004)
6. **RBAC** (KR-ACCESS-003)
7. **Revisionsloggning** (KR-ACCESS-004)
8. **Storleksgränser för requests** (KR-CONFIG-003)
9. **Output-sanering** (KR-XSS-001, KR-XSS-002)

### 🟢 ÖNSKVÄRD (Trevligt att ha)

1. **Refresh tokens** (KR-AUTH-007)
2. **Request-loggning** (KR-DATA-005)
3. **Resursnivå-behörigheter** (KR-ACCESS-005)
4. **CSP-headers** (KR-XSS-004)
5. **Logg-rotation** (KR-LOG-005)

---

## Implementeringsplan

### Fas 1: Kritisk säkerhet (Vecka 1)
- Implementera bcrypt-lösenordshashing
- Lägg till JWT med utgång
- Konfigurera hastighetsbegränsning
- Sätt upp miljövariabler
- Aktivera HTTPS

### Fas 2: Autentiseringshärdning (Vecka 2)
- Stark lösenordspolicy
- Kontolåsningsmekanism
- Input-sanering
- Säkerhetsheaders

### Fas 3: Övervakning & åtkomstkontroll (Vecka 3)
- Omfattande loggning
- Revisionsspår
- RBAC-implementation
- Auktoriseringsförbättringar

### Fas 4: Avancerad säkerhet (Vecka 4+)
- Refresh token-mekanism
- Avancerad övervakning
- Automatiserad säkerhetstestning
- Penetrationstestning

---

## Testchecklista

- [ ] Alla autentiseringstester godkända
- [ ] Hastighetsbegränsning fungerar korrekt
- [ ] Tokens upphör som förväntat
- [ ] Input-validering fångar skadlig input
- [ ] CORS konfigurerad korrekt
- [ ] Säkerhetsheaders närvarande
- [ ] Loggar fångar säkerhetshändelser
- [ ] Användarisolering verifierad
- [ ] Felmeddelanden läcker inte information
- [ ] Miljövariabler korrekt konfigurerade

---

## Referenser

- [OWASP Top 10 2021](https://owasp.org/Top10/)
-