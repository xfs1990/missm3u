addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

const baseUrl = 'https://surrit.com';
const secret = 'Pass520'; // 自定义密钥

async function handleRequest(request) {
  const url = new URL(request.url);
  let path = url.pathname;

  const newPathPrefix = '/v/';
  if (path.startsWith(newPathPrefix)) {
    path = path.replace(newPathPrefix, '/');
  } else {
    return new Response('无权访问！', { status: 410, headers: getCORSHeaders() });
  }

  const headers = new Headers({
    'accept': 'video/*;q=0.9,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'cache-control': 'no-cache',
    'pragma': 'no-cache',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    'sec-fetch-dest': 'video',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site'
  });

  let targetPath = path;

  // 映射 .log → .jpeg（源站真实路径）
  if (targetPath.endsWith('.log')) {
    targetPath = targetPath.replace(/\.log$/, '.jpeg');
  }

  const targetUrl = `${baseUrl}${targetPath}`;

  // ✅ 处理 m3u8 签名验证
  if (path.endsWith('.m3u8')) {
    const expires = url.searchParams.get('expires');
    const signature = url.searchParams.get('signature');

    if (!expires || !signature) {
      return new Response('缺少签名或有效期', { status: 403, headers: getCORSHeaders() });
    }

    const now = Math.floor(Date.now() / 1000);
    if (now > parseInt(expires)) {
      return new Response('URL 已过期', { status: 403, headers: getCORSHeaders() });
    }

    const rawUrl = url.origin + url.pathname;
    const expectedSignature = await generateHmac(rawUrl + expires, secret);

    if (signature !== expectedSignature) {
      return new Response('签名不匹配', { status: 403, headers: getCORSHeaders() });
    }

    // 请求源站并替换 .jpeg 为 .log
    const response = await fetch(targetUrl, {
      method: request.method,
      headers,
      cf: { cacheEverything: false, cacheTtl: 0 }
    });

    const text = await response.text();
    const modifiedText = text.replace(/\.jpeg(\?[^"'\s]*)?/g, '.log$1');

    return new Response(modifiedText, {
      status: response.status,
      headers: {
        ...getCORSHeaders(),
        'Content-Type': 'application/vnd.apple.mpegurl'
      }
    });
  }

  // ✅ .log → 源站 .jpeg
  if (path.endsWith('.log')) {
    const imageResponse = await fetch(targetUrl, {
      method: request.method,
      headers,
      cf: { cacheEverything: false, cacheTtl: 0 }
    });

    const jpegHeaders = new Headers(imageResponse.headers);
    jpegHeaders.set('Cache-Control', 'public, max-age=2592000');

    return new Response(imageResponse.body, {
      status: imageResponse.status,
      headers: {
        ...getCORSHeaders(),
        ...Object.fromEntries(jpegHeaders.entries())
      }
    });
  }

  // 其他资源默认转发
  const response = await fetch(targetUrl, {
    method: request.method,
    headers,
    cf: { cacheEverything: false, cacheTtl: 0 }
  });

  return new Response(response.body, {
    status: response.status,
    headers: {
      ...getCORSHeaders(),
      'Content-Type': response.headers.get('Content-Type') || 'application/octet-stream'
    }
  });
}

// ✅ 签名生成 HMAC-SHA256
async function generateHmac(message, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ✅ 跨域响应头
function getCORSHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range',
    'Access-Control-Expose-Headers': 'Content-Length,Content-Range'
  };
}
