# Keep the newest complete lines without separating untrusted text from its prefix.
BEGIN {
  first = 1
}

{
  buffer[NR] = $0 ORS
  sizes[NR] = length($0) + length(ORS)
  total += sizes[NR]
  while (total > limit && first <= NR) {
    total -= sizes[first]
    delete buffer[first]
    delete sizes[first]
    first++
  }
}

END {
  for (i = first; i <= NR; i++) {
    printf "%s", buffer[i]
  }
}
