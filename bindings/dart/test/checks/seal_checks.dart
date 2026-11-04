import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void run() {
  test('seal and unseal a local key', () {
    if (!hasSeal()) {
      markTestSkipped('kcb2.seal unavailable in this build');
      return;
    }
    final r = RecipientKey.generate();
    final rp = r.publicKey();
    final rec = rp.toPaserk();
    expect(rec, startsWith('kcb2.recipient.'));
    expect(rec.length, 1637);
    final secret = r.toPaserk();
    expect(secret.length, 65);
    final r2 = RecipientKey.fromPaserk(secret);
    final k = LocalKey.generate();
    final sealed = Seal.seal(rp, k);
    expect(sealed.length, 1632);
    final back = Seal.unseal(sealed, r2);
    expect(back.paserkId, k.paserkId);
    final other = RecipientKey.generate();
    expect(() => Seal.unseal(sealed, other), verdict('invalid'));
    expect(rp.paserkId, r2.paserkId);
    expect(rp.paserkId, startsWith('kcb2.rid.'));
    expect(RecipientPublicKey.fromPaserk(rec).paserkId, rp.paserkId);
  });
}
