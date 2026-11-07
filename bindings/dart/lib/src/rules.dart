import 'package:cb2/src/holder_rules.dart';
import 'package:cb2/src/replay_check.dart';

/// The rules a claims token is checked against, one field per member of
/// the rules JSON of cb2_c.h. Times are Unix seconds.
///
/// [replay] is run for the jti of the token, a callback that throws
/// refuses the id; [holder] checks a holder proof.
final class Rules {
  /// Rules with the given members; a null member is left out of the JSON.
  const factory Rules({
    int? now,
    int? clockSkew,
    bool? requireExp,
    bool? allowAnyAudience,
    bool? allowAnyIssuer,
    String? issuer,
    String? audience,
    String? subject,
    int? maxTokenBytes,
    int? maxLifetime,
    ReplayCheck? replay,
    List<String>? seenJti,
    bool? requireCnf,
    bool? ignoreCnf,
    HolderRules? holder,
  }) = Rules._;

  const Rules._({
    this.now,
    this.clockSkew,
    this.requireExp,
    this.allowAnyAudience,
    this.allowAnyIssuer,
    this.issuer,
    this.audience,
    this.subject,
    this.maxTokenBytes,
    this.maxLifetime,
    this.replay,
    this.seenJti,
    this.requireCnf,
    this.ignoreCnf,
    this.holder,
  });

  /// The time of the check in Unix seconds; the library clock when null.
  final int? now;

  /// The leeway in seconds granted to exp, nbf and iat.
  final int? clockSkew;

  /// Whether a token without exp is refused.
  final bool? requireExp;

  /// Whether any aud is accepted when [audience] is null.
  final bool? allowAnyAudience;

  /// Whether any iss is accepted when [issuer] is null.
  final bool? allowAnyIssuer;

  /// The iss the token must carry.
  final String? issuer;

  /// The aud the token must name.
  final String? audience;

  /// The sub the token must carry.
  final String? subject;

  /// The largest token accepted, in bytes; the library default when null.
  final int? maxTokenBytes;

  /// The longest exp minus iat accepted, in seconds.
  final int? maxLifetime;

  /// The replay check run for the jti of the token.
  final ReplayCheck? replay;

  /// Ids already seen; a token whose jti is listed is refused.
  final List<String>? seenJti;

  /// Whether a token without a cnf claim is refused.
  final bool? requireCnf;

  /// Whether a cnf claim is left unchecked, for a resource that reads it.
  final bool? ignoreCnf;

  /// The check of the holder proof presented with the token.
  final HolderRules? holder;
}
