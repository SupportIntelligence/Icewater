
rule m2321_0b1d8690dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b1d8690dee30912"
     cluster="m2321.0b1d8690dee30912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery dynamer pemalform"
     md5_hashes="['8545bdf22c458659d4a7e5eb60497622','ca77977acb576cf28a22c9ad9f0ac24c','e29fc8f23d2817fd41942a796616e6fc']"

   strings:
      $hex_string = { 90f73bbbf1c88a67ac8d51e273d53a499f5be8029b1483295f302e634128aab424682cdd6f74ef377a944bb7750f79432fdb4d73825808fc923fa2cdc2a5629d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
