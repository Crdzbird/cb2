import 'package:cb2/src/ffi/cb2_bindings.dart';
import 'package:cb2/src/library.dart';

/// The bindings of the library [Cb2Library.open] finds, opened on the
/// first call into cb2 and kept for the life of the isolate.
final Cb2Bindings bindings = Cb2Bindings(Cb2Library.open());
