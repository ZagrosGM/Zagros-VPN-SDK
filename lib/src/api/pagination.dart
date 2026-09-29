import '../models/error.dart';

class CursorPage<T> {
  CursorPage({required List<T> items, this.nextCursor})
      : items = List<T>.unmodifiable(items);
  final List<T> items;
  final String? nextCursor;
}

Stream<T> paginate<T>({
  required Future<CursorPage<T>> Function(String? cursor) load,
  int maximumPages = 1000,
}) async* {
  if (maximumPages < 1) throw ArgumentError.value(maximumPages, 'maximumPages');
  final seen = <String>{};
  String? cursor;
  for (var pageNumber = 0; pageNumber < maximumPages; pageNumber += 1) {
    final page = await load(cursor);
    for (final item in page.items) {
      yield item;
    }
    final next = page.nextCursor;
    if (next == null) return;
    if (next.isEmpty || !seen.add(next)) {
      throw const ZagrosException(
        ZagrosErrorKind.malformedResponse,
        'Application API returned an invalid pagination cursor',
      );
    }
    cursor = next;
  }
  throw const ZagrosException(
    ZagrosErrorKind.malformedResponse,
    'Application API pagination exceeded its safety limit',
  );
}
