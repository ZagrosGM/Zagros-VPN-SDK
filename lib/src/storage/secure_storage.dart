/// Platform clients must implement this using an OS-protected secret store.
/// White-label mode must never provide a plaintext file/preferences fallback.
abstract interface class SecureValueStore {
  /// Returned bytes must be a caller-owned copy.
  Future<List<int>?> read(String key);

  /// Must consume/copy [value] before the returned future completes.
  Future<void> write(String key, List<int> value);
  Future<void> delete(String key);
}

/// Token storage is separate from raw configuration. Implementations must use
/// OS-secure storage and must not log values.
abstract interface class SecureTokenStore {
  Future<String?> read();
  Future<void> write(String serializedTokens);
  Future<void> delete();
}
