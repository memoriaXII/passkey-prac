/**
 * Encodes an ArrayBuffer to a Base64 URL string
 * @param {ArrayBuffer} buffer - The buffer to encode
 * @returns {string} The Base64 URL encoded string
 */
export function base64UrlEncode(buffer) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Decodes a Base64 URL string to an ArrayBuffer
 * @param {string} base64Url - The Base64 URL string to decode
 * @returns {ArrayBuffer} The decoded ArrayBuffer
 */
export function base64UrlDecode(base64Url) {
  const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');

  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }

  return outputArray.buffer;
}

/**
 * Converts a string to an ArrayBuffer
 * @param {string} str - The string to convert
 * @returns {ArrayBuffer} The resulting ArrayBuffer
 */
export function stringToArrayBuffer(str) {
  return new TextEncoder().encode(str);
}

/**
 * Converts an ArrayBuffer to a string
 * @param {ArrayBuffer} buffer - The buffer to convert
 * @returns {string} The resulting string
 */
export function arrayBufferToString(buffer) {
  return new TextDecoder().decode(buffer);
}
