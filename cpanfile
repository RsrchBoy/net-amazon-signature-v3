requires "Digest::HMAC_SHA1" => "0";
requires "HTTP::Date" => "0";
requires "MIME::Base64" => "0";
requires "Moose" => "0";
requires "MooseX::AttributeShortcuts" => "0.015";
requires "MooseX::Types::Common::String" => "0";
requires "namespace::autoclean" => "0";
requires "perl" => "5.008";
requires "utf8" => "0";

on 'test' => sub {
  requires "ExtUtils::MakeMaker" => "0";
  requires "File::Spec" => "0";
  requires "IO::Handle" => "0";
  requires "IPC::Open3" => "0";
  requires "Test::CheckDeps" => "0.010";
  requires "Test::Moose::More" => "0";
  requires "Test::More" => "0.94";
  requires "aliased" => "0";
  requires "perl" => "5.008";
  requires "strict" => "0";
  requires "warnings" => "0";
};

on 'test' => sub {
  recommends "CPAN::Meta" => "2.120900";
};

on 'configure' => sub {
  requires "ExtUtils::MakeMaker" => "0";
  requires "perl" => "5.008";
};

on 'develop' => sub {
  requires "Pod::Coverage::TrustPod" => "0";
  requires "Pod::Wordlist" => "0";
  requires "Test::ConsistentVersion" => "0";
  requires "Test::EOL" => "0";
  requires "Test::HasVersion" => "0";
  requires "Test::MinimumVersion" => "0";
  requires "Test::More" => "0.88";
  requires "Test::NoSmartComments" => "0";
  requires "Test::NoTabs" => "0";
  requires "Test::Pod" => "1.41";
  requires "Test::Pod::Coverage" => "1.08";
  requires "Test::Pod::LinkCheck" => "0";
  requires "Test::Spelling" => "0.12";
  requires "strict" => "0";
  requires "warnings" => "0";
};
