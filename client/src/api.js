const defaultHeaders = {
  'Content-Type': 'application/json',
};

async function handleResponse(response) {
  const contentType = response.headers.get('content-type') || '';
  let body = null;
  if (contentType.includes('application/json')) {
    body = await response.json();
  } else {
    body = await response.text();
  }
  if (!response.ok) {
    const error = typeof body === 'string' ? { message: body } : body || {};
    throw new Error(error.error || error.message || 'Request failed');
  }
  return body;
}

export async function apiGet(path) {
  const response = await fetch(path, {
    credentials: 'include',
  });
  return handleResponse(response);
}

export async function apiPost(path, body, options = {}) {
  const isFormData = body instanceof FormData;
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers: isFormData ? options.headers : { ...defaultHeaders, ...options.headers },
    body: isFormData ? body : JSON.stringify(body || {}),
  });
  return handleResponse(response);
}

export async function apiDelete(path) {
  const response = await fetch(path, {
    method: 'DELETE',
    credentials: 'include',
  });
  return handleResponse(response);
}
