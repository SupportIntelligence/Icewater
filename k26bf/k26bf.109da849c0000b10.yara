
rule k26bf_109da849c0000b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bf.109da849c0000b10"
     cluster="k26bf.109da849c0000b10"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu malicious engine"
     md5_hashes="['6b84734f67979015d0259766836bc93bc22d428c','0a5c24f9080c34fd8d6a5c1936745ab598db5a8e','43026a68eb0cf1e701994a8ab7de40cae0413571']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bf.109da849c0000b10"

   strings:
      $hex_string = { 650048656c704b6579776f72644174747269627574650047656e657261746564436f64654174747269627574650044656275676765724e6f6e55736572436f64 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
