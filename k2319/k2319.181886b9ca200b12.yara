
rule k2319_181886b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181886b9ca200b12"
     cluster="k2319.181886b9ca200b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['7d5bba35e0f25e4f1d3496a36a68f0cc6608a357','6bd8fda430267d2fdaa00cc4d2602d5a56550aa1','aaad2a3181f9594b58f9987945308f50ba48f694']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181886b9ca200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20755b4f5d3b7d76617220473d28307843413c2835322e2c3078323138293f283131372e2c30786363396532643531293a2834 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
