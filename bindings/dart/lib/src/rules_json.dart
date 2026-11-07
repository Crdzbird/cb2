import 'package:cb2/src/holder_rules.dart';
import 'package:cb2/src/rules.dart';

/// The rules JSON object of cb2_c.h for a [Rules].
extension RulesJson on Rules {
  /// The rules JSON object; "replay" is set when [replay] is given.
  Map<String, Object?> toJson() => {
    if (now != null) 'now': now,
    if (clockSkew != null) 'clock_skew': clockSkew,
    if (requireExp != null) 'require_exp': requireExp,
    if (allowAnyAudience != null) 'allow_any_audience': allowAnyAudience,
    if (allowAnyIssuer != null) 'allow_any_issuer': allowAnyIssuer,
    if (issuer != null) 'issuer': issuer,
    if (audience != null) 'audience': audience,
    if (subject != null) 'subject': subject,
    if (maxTokenBytes != null) 'max_token_bytes': maxTokenBytes,
    if (maxLifetime != null) 'max_lifetime': maxLifetime,
    if (replay != null) 'replay': true,
    if (seenJti != null) 'seen_jti': seenJti,
    if (requireCnf != null) 'require_cnf': requireCnf,
    if (ignoreCnf != null) 'ignore_cnf': ignoreCnf,
    if (holder case final HolderRules h) ...{
      'proof': h.proof,
      'request': h.request.toJson(),
      if (h.lifetime != null) 'proof_lifetime': h.lifetime,
      if (h.seenJti != null) 'proof_seen_jti': h.seenJti,
    },
  };
}
