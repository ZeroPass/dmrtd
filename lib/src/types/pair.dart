// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.

class Pair<T1, T2> {
  /// Returns the first item of the pair
  final T1 first;

  /// Returns the second item of the pair
  final T2 second;

  /// Creates a new [Pair] with items [first] and [second].
  const Pair(this.first, this.second);
}