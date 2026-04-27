import express from 'express';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import dns from 'dns/promises';
import tls from 'tls';
import { URL } from 'url';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

// خدمة ملفات الواجهة الثابتة
app.use(express.static(path.join(__dirname, 'public')));

// إرسال log إلى الواجهة
function sendLog(ws, message, className = 't-dim') {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify({ type: 'log', message, className }));
  }
}

// إرسال تقدم العمليّة
function sendProgress(ws, percent, moduleName) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify({ type: 'progress', percent, moduleName }));
  }
}

// إرسال ثغرة مكتشفة
function sendFinding(ws, finding) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify({ type: 'finding', finding }));
  }
}

// إرسال إشارة انتهاء الفحص
function sendComplete(ws, stats) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify({ type: 'complete', stats }));
  }
}

// دالة مساعدة لبناء كائن الثغرة
function buildFinding(id, title, severity, cvss, cvssVector, module, description, impact, remediation, references, tags) {
  return { id, title, severity, cvss, cvssVector, module, description, impact, remediation, references, tags };
}

/* ================ وحدات الفحص الحقيقي ================ */

// 1. فحص SSL/TLS
async function checkSSL(ws, targetUrl, stopSignal) {
  sendLog(ws, '╔══ MODULE 1 : SSL/TLS ANALYSIS ══════════════════════╗', 't-head');
  const urlObj = new URL(targetUrl);
  const host = urlObj.hostname;
  const port = urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80);

  if (stopSignal.stopped) return;

  // التحقق من HTTPS
  if (urlObj.protocol !== 'https:') {
    sendLog(ws, '[CRITICAL] Protocol: HTTP — No Encryption!', 't-crit');
    sendFinding(ws, buildFinding('SSL-001', 'لا يوجد تشفير HTTPS', 'critical', 9.1,
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', 'SSL/TLS',
      'الموقع يستخدم HTTP فقط مما يعني أن جميع البيانات تُنقل بدون تشفير.',
      'يمكن لمهاجم على نفس الشبكة اعتراض بيانات المستخدمين بالكامل (كلمات المرور، ملفات تعريف الارتباط...).',
      'فعّل HTTPS عبر شهادة SSL صالحة واستخدم إعادة توجيه 301 من HTTP إلى HTTPS.',
      ['CWE-319', 'OWASP A02:2021', 'RFC 7230'],
      ['encryption', 'mitm', 'credentials']
    ));
    return;
  }

  // الاتصال بـ TLS لفحص الشهادة
  try {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      if (stopSignal.stopped) { socket.end(); return; }
      const cert = socket.getPeerCertificate();
      if (!cert || Object.keys(cert).length === 0) {
        sendLog(ws, '[WARN] شهادة رقمية غير مكتملة أو ذاتية التوقيع', 't-warn');
        sendFinding(ws, buildFinding('SSL-003', 'شهادة SSL غير صالحة أو ذاتية التوقيع', 'high', 7.5,
          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 'SSL/TLS',
          'الشهادة المستخدمة غير موثوقة أو غير مكتملة، مما يمنع التحقق من هوية الموقع.',
          'يمكن للمهاجم تنفيذ هجوم Man-in-the-Middle بسهولة.',
          'استخدم شهادة صادرة من هيئة موثوقة (مثلاً Let’s Encrypt).',
          ['CWE-295'],
          ['ssl', 'self-signed']
        ));
      } else {
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysLeft = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

        sendLog(ws, '[OK] Protocol: HTTPS ✓', 't-ok');
        sendLog(ws, `[INFO] TLS version: ${socket.getProtocol() || 'تعذر تحديد الإصدار'}`, 't-info');

        // صلاحية الشهادة
        if (now > validTo || now < validFrom) {
          sendLog(ws, `[CRITICAL] الشهادة منتهية الصلاحية (تنتهي ${validTo.toISOString().slice(0,10)})`, 't-crit');
          sendFinding(ws, buildFinding('SSL-002', 'شهادة SSL منتهية الصلاحية', 'critical', 9.1,
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', 'SSL/TLS',
            'الشهادة منتهية الصلاحية، والمتصفحات تحذر المستخدمين أو تمنع الاتصال.',
            'فقدان ثقة المستخدمين وإمكانية انتحال الموقع.',
            'قم بتجديد الشهادة فوراً.',
            ['CWE-298'],
            ['ssl', 'expired']
          ));
        } else if (daysLeft < 30) {
          sendLog(ws, `[WARN] الشهادة ستنتهي خلال ${daysLeft} يوم`, 't-warn');
        } else {
          sendLog(ws, `[OK] صلاحية الشهادة: ${daysLeft} يوم متبقية`, 't-ok');
        }
      }
      socket.end();
    });

    socket.on('error', (err) => {
      sendLog(ws, `[ERROR] فشل اتصال TLS: ${err.message}`, 't-err');
      sendFinding(ws, buildFinding('SSL-004', 'فشل التحقق من TLS', 'medium', 5.9,
        'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L', 'SSL/TLS',
        'حدث خطأ أثناء محاولة التحقق من TLS.',
        'قد يشير إلى إعدادات خاطئة أو جدار حماية يمنع الفحص.',
        'تأكد من أن الخادم يستجيب على المنفذ 443 ومن صحة إعدادات TLS.',
        ['CWE-523'],
        ['tls', 'error']
      ));
    });
    // انتظار قصير للتأكد من انتهاء العملية
    await new Promise(res => setTimeout(res, 500));
  } catch (err) {
    sendLog(ws, `[ERROR] فشل في فحص SSL: ${err.message}`, 't-err');
  }
}

// 2. فحص رؤوس الأمان HTTP
async function checkHeaders(ws, targetUrl, stopSignal) {
  sendLog(ws, '╔══ MODULE 2 : HTTP SECURITY HEADERS ═══════════════════╗', 't-head');
  if (stopSignal.stopped) return;
  try {
    const response = await fetch(targetUrl, {
      redirect: 'follow',
      headers: { 'User-Agent': 'BugBountyRecon/3.0' }
    });
    const headers = response.headers;

    const checks = [
      { name: 'Strict-Transport-Security', key: 'strict-transport-security',
        findingId: 'HDR-001', title: 'HSTS مفقود', severity: 'medium', cvss: 5.4,
        description: 'رأس HSTS غير موجود، مما يسمح بتنفيذ هجمات SSL Stripping.',
        impact: 'يمكن للمهاجم إجبار المتصفح على استخدام HTTP بدلاً من HTTPS في بعض السيناريوهات.',
        remediation: 'أضف: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        ref: ['RFC 6797', 'OWASP HSTS Cheat Sheet'], tags: ['hsts', 'ssl-stripping']
      },
      { name: 'X-Frame-Options', key: 'x-frame-options',
        findingId: 'HDR-002', title: 'X-Frame-Options مفقود — خطر Clickjacking', severity: 'medium', cvss: 6.1,
        description: 'غياب X-Frame-Options يسمح بتضمين الموقع داخل iframe في مواقع خبيثة.',
        impact: 'هجمات Clickjacking تخدع المستخدمين لأداء إجراءات غير مقصودة.',
        remediation: 'أضف: X-Frame-Options: DENY أو SAMEORIGIN',
        ref: ['CWE-1021', 'OWASP Clickjacking Defense'], tags: ['clickjacking', 'iframe']
      },
      { name: 'X-Content-Type-Options', key: 'x-content-type-options',
        findingId: 'HDR-003', title: 'X-Content-Type-Options مفقود — MIME Sniffing', severity: 'low', cvss: 3.7,
        description: 'غياب nosniff يسمح للمتصفح بتخمين نوع المحتوى وقد يؤدي لتنفيذ محتوى خبيث.',
        impact: 'MIME confusion attacks في بعض الحالات.',
        remediation: 'أضف: X-Content-Type-Options: nosniff',
        ref: ['CWE-16'], tags: ['mime', 'sniffing']
      },
      { name: 'Referrer-Policy', key: 'referrer-policy',
        findingId: 'HDR-004', title: 'Referrer-Policy مفقود — تسريب URL', severity: 'low', cvss: 3.1,
        description: 'بدون Referrer-Policy، قد تُرسل معلومات URL الحساسة إلى مواقع خارجية.',
        impact: 'تسريب tokens أو session IDs الموجودة في URL.',
        remediation: 'أضف: Referrer-Policy: strict-origin-when-cross-origin',
        ref: ['MDN Referrer-Policy'], tags: ['privacy', 'url-leakage']
      },
      { name: 'Permissions-Policy', key: 'permissions-policy',
        findingId: 'HDR-005', title: 'Permissions-Policy مفقود — صلاحيات مفتوحة', severity: 'low', cvss: 2.7,
        description: 'لا توجد سياسة لتقييد وصول الموقع إلى ميكروفون / كاميرا / موقع.',
        impact: 'كود خبيث مُدرج قد يصل لموارد المستخدم.',
        remediation: 'أضف: Permissions-Policy: geolocation=(), microphone=(), camera=()',
        ref: ['W3C Permissions Policy'], tags: ['browser-api', 'privacy']
      },
      { name: 'Content-Security-Policy', key: 'content-security-policy',
        findingId: 'HDR-006', title: 'Content Security Policy (CSP) غائبة', severity: 'high', cvss: 7.4,
        description: 'غياب CSP يجعل الموقع عرضة لهجمات XSS حيث لا توجد قيود على تنفيذ السكربتات.',
        impact: 'أي ثغرة XSS يمكن استغلالها بسهولة لسرقة cookies وبيانات المستخدمين.',
        remediation: "أضف CSP مثل: Content-Security-Policy: default-src 'self'; script-src 'self'",
        ref: ['OWASP CSP Cheat Sheet', 'CWE-693'], tags: ['xss', 'csp', 'injection']
      }
    ];

    for (const check of checks) {
      if (stopSignal.stopped) break;
      const headerValue = headers.get(check.key);
      if (headerValue) {
        sendLog(ws, `[OK] ${check.name}: Present ✓`, 't-ok');
      } else {
        sendLog(ws, `[MISS] ${check.name}: Missing ✗`, 't-warn');
        sendFinding(ws, {
          id: check.findingId,
          title: check.title,
          severity: check.severity,
          cvss: check.cvss,
          cvssVector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`,
          module: 'HTTP Headers',
          description: check.description,
          impact: check.impact,
          remediation: check.remediation,
          references: check.ref,
          tags: check.tags
        });
      }
    }
  } catch (err) {
    sendLog(ws, `[ERROR] فشل جلب رؤوس HTTP: ${err.message}`, 't-err');
  }
}

// 3. فحص CORS
async function checkCORS(ws, targetUrl, stopSignal) {
  sendLog(ws, '╔══ MODULE 3 : CORS ANALYSIS ══════════════════════╗', 't-head');
  if (stopSignal.stopped) return;
  try {
    const response = await fetch(targetUrl, {
      redirect: 'follow',
      headers: { 'User-Agent': 'BugBountyRecon/3.0' }
    });
    const acao = response.headers.get('access-control-allow-origin');
    const acac = response.headers.get('access-control-allow-credentials');

    if (!acao) {
      sendLog(ws, '[OK] CORS غير مفعل (آمن) — لا يسمح بطلبات cross-origin', 't-ok');
    } else if (acao === '*') {
      sendLog(ws, '[WARN] Access-Control-Allow-Origin: * (مفتوح لجميع النطاقات)', 't-warn');
      if (acac && acac.toLowerCase() === 'true') {
        sendLog(ws, '[CRITICAL] CORS + Credentials: يسمح بإرسال الكوكيز مع أي نطاق!', 't-crit');
        sendFinding(ws, buildFinding('CRS-001', 'CORS Misconfiguration — Wildcard + Credentials', 'critical', 9.3,
          'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N', 'CORS',
          'الموقع يسمح لأي نطاق (*) بإرسال طلبات مع بيانات اعتماد (cookies، رؤوس المصادقة).',
          'يمكن لأي موقع خبيث قراءة بيانات المستخدمين الحساسة أثناء تسجيل دخولهم.',
          'لا تستخدم * مع Access-Control-Allow-Credentials: true. حدد النطاقات الموثوقة فقط.',
          ['CWE-346', 'PortSwigger CORS Lab'], ['cors', 'credentials', 'csrf']
        ));
      } else {
        sendFinding(ws, buildFinding('CRS-002', 'CORS Misconfiguration — Wildcard Origin', 'medium', 5.3,
          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 'CORS',
          'الموقع يقبل طلبات من أي origin مما يفتح الباب لبعض هجمات cross-origin.',
          'قد يسمح بقراءة بيانات عامة من مواقع خارجية.',
          'قيد Access-Control-Allow-Origin إلى نطاقك المحدد بدلاً من *',
          ['MDN CORS', 'OWASP CORS Cheat Sheet'], ['cors', 'origin']
        ));
      }
    } else {
      sendLog(ws, `[INFO] CORS مقيد بـ: ${acao}`, 't-info');
    }
  } catch (err) {
    sendLog(ws, `[ERROR] فحص CORS: ${err.message}`, 't-err');
  }
}

// 4. فحص Information Disclosure
async function checkInfoDisclosure(ws, targetUrl, stopSignal) {
  sendLog(ws, '╔══ MODULE 4 : INFORMATION DISCLOSURE ═══════════════════╗', 't-head');
  if (stopSignal.stopped) return;
  const base = targetUrl.replace(/\/$/, '');
  const paths = [
    { path: '/.env',           risk: 'critical' },
    { path: '/.git/HEAD',      risk: 'critical' },
    { path: '/backup.zip',     risk: 'critical' },
    { path: '/config.php.bak', risk: 'high' },
    { path: '/phpinfo.php',    risk: 'high' },
    { path: '/server-status',  risk: 'medium' },
    { path: '/robots.txt',     risk: 'info' },
    { path: '/sitemap.xml',    risk: 'info' },
  ];

  for (const item of paths) {
    if (stopSignal.stopped) break;
    try {
      const res = await fetch(base + item.path, { method: 'GET', redirect: 'follow' });
      if (res.ok) {
        const sev = item.risk;
        const cvssMap = { critical: 9.8, high: 7.5, medium: 5.3, info: 0 };
        const findingSEv = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low';
        sendLog(ws, `[FOUND] ${base}${item.path}  ← متاح علناً!`, 't-warn');
        if (sev !== 'info') {
          sendFinding(ws, buildFinding(
            `INF-${item.path.replace(/\W/g, '')}`,
            `ملف حساس مكشوف: ${item.path}`,
            findingSEv,
            cvssMap[sev] || 3.1,
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'Info Disclosure',
            `الملف ${item.path} متاح للعامة وقد يحتوي على بيانات سرية (مفاتيح API، إعدادات قاعدة بيانات...).`,
            sev === 'critical' ? 'اختراق كامل محتمل — قد يحتوي على مفاتيح سرية أو بيانات اعتماد.' : 'تسريب معلومات يسهل التخطيط لهجمات أعمق.',
            'احذف الملف أو امنع الوصول إليه عبر إعدادات الخادم (مثلاً باستخدام .htaccess).',
            ['CWE-538', 'OWASP Information Leakage'],
            ['exposure', 'information-disclosure']
          ));
        }
      } else {
        sendLog(ws, `[----] ${base}${item.path} (غير متاح)`, 't-dim');
      }
    } catch (err) {
      sendLog(ws, `[----] ${base}${item.path} (خطأ أو غير موجود)`, 't-dim');
    }
  }
}

// 5. فحص المسارات الحساسة
async function checkSensitivePaths(ws, targetUrl, stopSignal) {
  sendLog(ws, '╔══ MODULE 5 : ADMIN / SENSITIVE ENDPOINTS ══════════════╗', 't-head');
  if (stopSignal.stopped) return;
  const base = targetUrl.replace(/\/$/, '');
  const adminPaths = ['/admin', '/dashboard', '/wp-admin', '/administrator', '/manager'];
  const apiPaths = ['/api', '/swagger', '/api-docs', '/graphql', '/.env']; // .env هنا للتأكيد

  // Admin
  for (const p of adminPaths) {
    if (stopSignal.stopped) break;
    try {
      const res = await fetch(base + p, { method: 'GET', redirect: 'follow' });
      if (res.ok) {
        sendLog(ws, `[200] ${base}${p}  ← لوحة تحكم مكشوفة`, 't-warn');
        sendFinding(ws, buildFinding(
          `PTH-${p.replace(/\W/g, '')}`,
          `لوحة إدارة مكشوفة: ${p}`,
          'high', 7.5,
          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N', 'Sensitive Paths',
          `المسار ${p} متاح بدون أي حماية، مما يعرض واجهة تسجيل الدخول أو لوحة التحكم.`,
          'يسمح بمحاولات التخمين أو استغلال ثغرات معروفة في لوحة الإدارة.',
          'انقل المسار إلى مسار مخصص أو قيّد الوصول عبر IP Whitelist.',
          ['CWE-425', 'OWASP A01:2021'], ['admin-panel', 'auth']
        ));
      } else {
        sendLog(ws, `[---] ${base}${p}`, 't-dim');
      }
    } catch (err) {
      sendLog(ws, `[---] ${base}${p}`, 't-dim');
    }
  }

  // API
  for (const p of apiPaths) {
    if (stopSignal.stopped) break;
    try {
      const res = await fetch(base + p, { method: 'GET', redirect: 'follow' });
      if (res.ok) {
        sendLog(ws, `[WARN] ${base}${p}  ← مكشوف`, 't-warn');
        sendFinding(ws, buildFinding(
          `API-${p.replace(/\W/g, '')}`,
          `نقطة API / توثيق مكشوفة: ${p}`,
          'medium', 5.3,
          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 'Sensitive Paths',
          `الخدمة ${p} متاحة علنياً وقد تكشف وثائق API داخلية.`,
          'تعطي المهاجم خريطة للـ API وتساعده على اكتشاف نقاط ضعف إضافية.',
          'أضف مصادقة أو أخفِ هذه النقاط خارج بيئة الإنتاج.',
          ['OWASP API Security Top 10'], ['api', 'documentation']
        ));
      } else {
        sendLog(ws, `[---] ${base}${p}`, 't-dim');
      }
    } catch (err) {
      sendLog(ws, `[---] ${base}${p}`, 't-dim');
    }
  }
}

// 6. DNS / Recon
async function checkDNS(ws, targetUrl, stopSignal) {
  sendLog(ws, '╔══ MODULE 6 : DNS / TECH FINGERPRINTING ════════════════╗', 't-head');
  if (stopSignal.stopped) return;
  const host = new URL(targetUrl).hostname;

  // DNS A Record
  try {
    const addresses = await dns.resolve4(host);
    const ip = addresses[0];
    sendLog(ws, `[DNS] A Record → ${ip}`, 't-info');
  } catch (err) {
    sendLog(ws, `[DNS] فشل تحليل A Record: ${err.message}`, 't-err');
  }

  // محاولة اكتشاف CDN عبر رؤوس الخادم
  try {
    const res = await fetch(targetUrl, { method: 'GET', headers: { 'User-Agent': 'BugBountyRecon/3.0' } });
    const server = res.headers.get('server') || '';
    const via = res.headers.get('via') || '';
    const xCache = res.headers.get('x-cache') || '';
    if (/cloudflare/i.test(server) || /cloudflare/i.test(via) || /cloudflare/i.test(xCache)) {
      sendLog(ws, '[CDN] Cloudflare detected ✓', 't-ok');
    } else if (/akamai/i.test(server) || /akamai/i.test(via)) {
      sendLog(ws, '[CDN] Akamai detected ✓', 't-ok');
    } else {
      sendLog(ws, '[CDN] لم يتم اكتشاف CDN — الخادم مباشر', 't-warn');
    }
  } catch (e) {
    sendLog(ws, '[CDN] تعذر التحقق من CDN', 't-dim');
  }
}

/* ================ معالجة WebSocket ================ */
wss.on('connection', (ws) => {
  let stopSignal = { stopped: false };

  ws.on('message', async (msg) => {
    let data;
    try {
      data = JSON.parse(msg);
    } catch (e) {
      sendLog(ws, 'رسالة غير صالحة', 't-err');
      return;
    }

    if (data.type === 'scan') {
      const target = data.target;
      let targetUrl = target;
      if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;

      // إعادة تعيين إشارة التوقف
      stopSignal.stopped = false;

      // تنفيذ الوحدات بالتتابع مع تحديث شريط التقدم
      const modules = [
        { fn: checkSSL, name: 'SSL/TLS', weight: 16 },
        { fn: checkHeaders, name: 'HTTP Headers', weight: 16 },
        { fn: checkCORS, name: 'CORS', weight: 16 },
        { fn: checkInfoDisclosure, name: 'Info Disclosure', weight: 16 },
        { fn: checkSensitivePaths, name: 'Sensitive Paths', weight: 16 },
        { fn: checkDNS, name: 'DNS/Recon', weight: 20 }
      ];

      let progress = 0;
      sendProgress(ws, progress, 'INIT');

      for (const mod of modules) {
        if (stopSignal.stopped) break;
        try {
          await mod.fn(ws, targetUrl, stopSignal);
        } catch (err) {
          sendLog(ws, `[ERROR] فشل تنفيذ ${mod.name}: ${err.message}`, 't-err');
        }
        progress += mod.weight;
        sendProgress(ws, Math.min(progress, 100), mod.name);
      }

      if (!stopSignal.stopped) {
        sendProgress(ws, 100, 'COMPLETE');
        sendComplete(ws, {});
      } else {
        sendLog(ws, '⏹ تم إيقاف الفحص بواسطة المستخدم', 't-info');
        sendProgress(ws, progress, 'STOPPED');
      }
    } else if (data.type === 'stop') {
      stopSignal.stopped = true;
      sendLog(ws, '⏹ جارٍ إيقاف الفحص...', 't-info');
    }
  });

  ws.on('close', () => {
    stopSignal.stopped = true;
  });
});

// تشغيل الخادم
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Bug Bounty Recon Platform running on http://localhost:${PORT}`);
});
