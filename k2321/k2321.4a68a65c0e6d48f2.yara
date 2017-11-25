
rule k2321_4a68a65c0e6d48f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.4a68a65c0e6d48f2"
     cluster="k2321.4a68a65c0e6d48f2"
     cluster_size="10"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['0cfc969e1a3280f5147b60f9ee359599','195801843809cd12e31ffa24b2a0dd74','e2c0583415d422d6a91d7b3902248708']"

   strings:
      $hex_string = { 116e96bfa4c6c3c585f244482847f8a56cf1672efc5c0d1845f5826b97e7ad7da8f67033b57b16d50caeeefdbc3529362663c1cf3eff00ea045c23c23bfa512f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
