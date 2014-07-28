$sha->reset();
  $sha->add( ( $passwd, $this->salt) );
  my $stretched = $sha->digest();
  foreach (1 .. $this->iter) {
    $sha->reset();
    $sha->add( ( $stretched) );
    $stretched = $sha->digest();
  }
  $passwd = $this->random(64);
  return $stretched;
