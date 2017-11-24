
rule k2321_0ec9547ac8146c56
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ec9547ac8146c56"
     cluster="k2321.0ec9547ac8146c56"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="yunsip zusy backdoor"
     md5_hashes="['6becbdc0b1271522e535a562f7c48368','970db04f2bdd09aed73692bccec08f13','f9e3f92f2b12aea3db6caa888e949edf']"

   strings:
      $hex_string = { 26bef36c01660f3c0bc0e1e6bcea8efd4af623e99aa9b175bb8c6e4bb6aea1fe69d38fcc2d8899361b7b8d541ae76fcdc12c81d75ada9f33d8646d62420a5ba7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
