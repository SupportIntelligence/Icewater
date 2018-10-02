
rule i2319_230d294cea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.230d294cea210912"
     cluster="i2319.230d294cea210912"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html phishing script"
     md5_hashes="['4c8855e2a7565743419cca680c4d7028c99bdd93','5bdb528dcad126b9831ee3dfab805db0b7f8b003','368563b54e86b53759fd38ed2bbdec77d0610ca2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.230d294cea210912"

   strings:
      $hex_string = { 636861727365743d77696e646f77732d31323532223e0d0a3c7469746c653e457863656c204f6e6c696e65202d2030394b534a444a52343834333938344e4639 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
