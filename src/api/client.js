// Varsayilan: arayuz ve API ayni kokenden sunulur (gelistirmede Vite vekili, uretimde arka uc).
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');

function apiFetch(path, options = {}) {
  return fetch(`${API_BASE_URL}${path}`, { credentials: 'include', ...options });
}

export async function analyzeUrl(urlToAnalyze) {
  let response;

  try {
    response = await apiFetch('/analyze/url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: urlToAnalyze }),
    });
  } catch {
    throw new Error('Analiz servisine ulaşılamadı. Bağlantınızı kontrol edip tekrar deneyin.');
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    if ([400, 413, 429, 503, 504].includes(response.status) && typeof errorData.detail === 'string') {
      throw new Error(errorData.detail);
    }
    if (response.status === 422) {
      throw new Error('Adres geçersiz veya çok uzun (en fazla 2048 karakter).');
    }
    throw new Error(`Analiz tamamlanamadı (HTTP ${response.status}). Lütfen tekrar deneyin.`);
  }

  return response.json();
}

export async function fetchBrands() {
  let response;
  try {
    response = await apiFetch('/brands');
  } catch {
    throw new Error('Katalog servisine ulaşılamadı.');
  }
  if (!response.ok) {
    throw new Error(`Katalog getirilemedi (HTTP ${response.status}).`);
  }
  return response.json();
}

// Yonetici oturumu yalnizca sunucunun koydugu HttpOnly; Secure; SameSite=Strict cerezde tutulur.
// Oturum anahtari JavaScript tarafindan okunamaz ve tarayici deposuna yazilmaz.
function clearLegacyToken() {
  try {
    localStorage.removeItem('cti_admin_token');
    sessionStorage.removeItem('cti_admin_token');
  } catch {
    /* depolama kullanilamiyor olabilir */
  }
}
clearLegacyToken();

export async function adminLogin(password, remember = false, otp = '') {
  const response = await apiFetch('/admin/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(otp ? { password, remember, otp } : { password, remember }),
  });

  if (!response.ok) {
    if (response.status === 429) {
      throw new Error('Çok fazla hatalı deneme yapıldı. Lütfen birkaç dakika sonra tekrar deneyin.');
    }
    const errorData = await response.json().catch(() => ({}));
    throw new Error(typeof errorData.detail === 'string' ? errorData.detail : 'Giriş başarısız. Parolanızı kontrol edin.');
  }

  return response.json();
}

export async function adminLogout() {
  try {
    await apiFetch('/admin/logout', { method: 'POST' });
  } catch {
    /* sunucuya ulasilamasa da arayuz oturumu kapatir */
  }
}

export async function adminVerify() {
  try {
    const response = await apiFetch('/admin/verify');
    if (!response.ok) {
      return { valid: false };
    }
    return await response.json();
  } catch {
    return { valid: false };
  }
}

export async function fetchAdminStats() {
  const response = await apiFetch('/admin/stats');
  if (!response.ok) {
    throw new Error('İstatistikler alınamadı.');
  }
  return response.json();
}

export async function fetchLists(listType) {
  const path = listType ? `/lists?list_type=${encodeURIComponent(listType)}` : '/lists';
  const response = await apiFetch(path);
  if (!response.ok) {
    throw new Error(`Liste getirilemedi (HTTP ${response.status}).`);
  }
  return response.json();
}

export async function addListItem(itemData) {
  const response = await apiFetch('/lists', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(itemData),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Kural eklenemedi (HTTP ${response.status}).`);
  }

  return response.json();
}

export async function deleteListItem(itemId) {
  const response = await apiFetch(`/lists/${encodeURIComponent(itemId)}`, {
    method: 'DELETE',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Kural silinemedi (HTTP ${response.status}).`);
  }

  return true;
}
