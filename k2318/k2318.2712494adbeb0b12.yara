
rule k2318_2712494adbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2712494adbeb0b12"
     cluster="k2318.2712494adbeb0b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['acabc263282297f2c0e56f34b62d2b936793e2d9','1c2df0c63d8507d1c063b92ef03c5d950637bea1','93c53a38fe4d3db1300ce710ca5ab2b8d5d6d45c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2712494adbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
