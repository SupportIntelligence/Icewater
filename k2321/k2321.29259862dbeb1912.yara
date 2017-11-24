
rule k2321_29259862dbeb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29259862dbeb1912"
     cluster="k2321.29259862dbeb1912"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt symmi"
     md5_hashes="['21b1e19cec4722de31815583186b7bc9','55216a071f4e0d2e2d5a6b7845d1de6f','f1f63d275562c60dee81d9fb8cc233e6']"

   strings:
      $hex_string = { 9bd6dc1e71ce629e39e028bdd7445b2d0d5672af89b23a1aac74735b1f75b31af36435aa2257e8c8c968df6cb447f66ebc1d8e5dfb43ba4b8a0bf57a54809169 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
