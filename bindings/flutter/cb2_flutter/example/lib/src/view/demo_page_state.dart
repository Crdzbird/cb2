import 'dart:isolate';

import 'package:cb2_flutter_example/src/demo/demo_step.dart';
import 'package:cb2_flutter_example/src/demo/step_outcome.dart';
import 'package:cb2_flutter_example/src/demo/token_demo.dart';
import 'package:cb2_flutter_example/src/view/demo_page.dart';
import 'package:cb2_flutter_example/src/view/intro_card.dart';
import 'package:cb2_flutter_example/src/view/step_tile.dart';
import 'package:flutter/material.dart';

/// Runs the demo off the UI isolate and shows its steps.
final class DemoPageState extends State<DemoPage> {
  /// The key of the button that runs the demo.
  static const runKey = Key('run-demo');

  List<DemoStep> _steps = const [];
  bool _running = false;

  Future<void> _run() async {
    setState(() => _running = true);
    final steps = await _demo();
    if (!mounted) {
      return;
    }
    setState(() {
      _steps = steps;
      _running = false;
    });
  }

  Future<List<DemoStep>> _demo() async {
    try {
      return await Isolate.run(runTokenDemo);
    } on Object catch (e) {
      return [
        DemoStep(
          title: 'Load the native library',
          detail: '$e',
          outcome: StepOutcome.failed,
        ),
      ];
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('cb2 tokens')),
    body: SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const IntroCard(),
          const SizedBox(height: 16),
          FilledButton.icon(
            key: runKey,
            onPressed: _running ? null : _run,
            icon: const Icon(Icons.play_arrow),
            label: Text(_running ? 'Running...' : 'Run the demo'),
          ),
          const SizedBox(height: 8),
          ..._steps.map(StepTile.new),
        ],
      ),
    ),
  );
}
