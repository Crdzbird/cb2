import 'package:flutter/material.dart';

/// Says what the demo does before it runs.
final class IntroCard extends StatelessWidget {
  /// The card.
  const factory IntroCard({Key? key}) = IntroCard._;

  const IntroCard._({super.key});

  @override
  Widget build(BuildContext context) => const Card(
    child: Padding(
      padding: EdgeInsets.all(16),
      child: Text(
        'Seals and opens a cb2.local token, signs and verifies a cb2.public '
        'token, and shows the library refusing a replayed token, a tampered '
        'token and a token for another audience. Everything runs in the '
        'native cb2 library, off the UI isolate.',
      ),
    ),
  );
}
