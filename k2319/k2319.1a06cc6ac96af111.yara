
rule k2319_1a06cc6ac96af111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a06cc6ac96af111"
     cluster="k2319.1a06cc6ac96af111"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script asmalwsc"
     md5_hashes="['3b7f2170082db911eccf16baabdafca9aab1c903','fa6f14455a14e7aec8cf5ee3076e70a0aadc92e2','7be9e10cd843c7bc760273bed34b606637538a6d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a06cc6ac96af111"

   strings:
      $hex_string = { 646566696e6564297b72657475726e20755b4f5d3b7d76617220473d2835332e3745313e3d28352e383345322c30784331293f28372e323245322c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
