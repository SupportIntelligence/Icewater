
rule k2318_331358c9c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.331358c9c6220b12"
     cluster="k2318.331358c9c6220b12"
     cluster_size="124"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['915b58885b99a9c0f5441bb14f3e7d55c662fd63','a232fb8f9fd769c1f39f210f550f892eeb98ff78','5b92c72cb75af8c1c5952cae4ea972ae398c6836']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.331358c9c6220b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
