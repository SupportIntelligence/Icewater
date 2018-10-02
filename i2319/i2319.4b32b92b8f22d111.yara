
rule i2319_4b32b92b8f22d111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.4b32b92b8f22d111"
     cluster="i2319.4b32b92b8f22d111"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos expkit html"
     md5_hashes="['6f37a3a28cc1ad7b9a765a70b21c42ad99489640','84d899a4eee58e2ee36ccc1231872839ab95cd91','6153d61a31991feb011723d2d2b610117add710b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.4b32b92b8f22d111"

   strings:
      $hex_string = { 5b302c20657870697265735f646174655d3b0d0a09090d0a20202020666f7220282069203d20303b2069203c20615f616c6c5f636f6f6b6965732e6c656e6774 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
