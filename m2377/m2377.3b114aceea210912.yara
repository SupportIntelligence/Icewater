
rule m2377_3b114aceea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.3b114aceea210912"
     cluster="m2377.3b114aceea210912"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['22a2cf765a4a3f92d959fa8f50e210e5','6837ef6a84dc58b87cc4623a076baa25','d1aa20825328cc322f849d4bf9a650f7']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d36303730313834373436333236323539343126776964676574547970653d4c6162656c26776964676574 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
