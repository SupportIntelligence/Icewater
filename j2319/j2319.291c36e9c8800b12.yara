
rule j2319_291c36e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.291c36e9c8800b12"
     cluster="j2319.291c36e9c8800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsermodifier multiplug diplugem"
     md5_hashes="['1d56f09592cb678f7f5c512c90ea10668825e822','c52953b0d8a3761847d55d640079efa4e3323214','05691e7929f4c5e44727150956a426d4896c08f7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.291c36e9c8800b12"

   strings:
      $hex_string = { 6528223f222c223f726d62733d31262229293b746869732e776f726b696e673d313b746869732e616a617843616c6c4261636b3d633b76617220623d646f6375 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
