
rule k2319_6906e750aa496f32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6906e750aa496f32"
     cluster="k2319.6906e750aa496f32"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script mnbfoky"
     md5_hashes="['94fe7d80e82ba4151651578e48c02f1bf7aa5f57','aba6c07385731e45f7adffad44252455f533fe4f','1e5d5ce16667fdb962856d95ee90e7b636826200']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6906e750aa496f32"

   strings:
      $hex_string = { 66696e6564297b72657475726e20465b765d3b7d766172204a3d2828307834352c3836293c3d312e33373745333f28307844362c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
