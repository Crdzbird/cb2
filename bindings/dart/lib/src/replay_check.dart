/// A replay check: returns true to accept the id, false to refuse it.
typedef ReplayCheck = bool Function(String jti);
