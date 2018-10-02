
rule k2318_3711290ebe210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3711290ebe210b12"
     cluster="k2318.3711290ebe210b12"
     cluster_size="138"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['32c051692204c404e7f49cfa5f9b4887b58a06f1','e18e9932d2eab75b86da04e71f66b4c8680a5811','68aac39b0a42617b3bd12748469cfe251548dd3e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3711290ebe210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
