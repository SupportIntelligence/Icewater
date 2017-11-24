
rule m2321_61954943ddeb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.61954943ddeb0912"
     cluster="m2321.61954943ddeb0912"
     cluster_size="89"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="socelars symmi socstealer"
     md5_hashes="['0930904cced2183683fe33951cd0bfdd','094aa72dfdb96e1ea572ac82c18a2753','36c6ebce7fca007f37a734602f8a9c85']"

   strings:
      $hex_string = { b3f121db3c0d0cf4993053c4269ca3cba0aad1010ba1723275fc07af500a7c4c572d9314c2f06351fd746e372c0f46105996b57e47c6f9eeb12438a5e2045eca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
