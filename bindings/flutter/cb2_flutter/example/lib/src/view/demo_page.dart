import 'package:cb2_flutter_example/src/view/demo_page_state.dart';
import 'package:flutter/material.dart';

/// The page that runs the token demo and lists its steps.
final class DemoPage extends StatefulWidget {
  /// The page, empty until the demo runs.
  const factory DemoPage({Key? key}) = DemoPage._;

  const DemoPage._({super.key});

  @override
  State<DemoPage> createState() => DemoPageState();
}
