
rule n2319_699492c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.699492c9c4000b12"
     cluster="n2319.699492c9c4000b12"
     cluster_size="70"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['503db7e27356e62385faf1f3f111038412f97e3c','6ca3d32c5261f5e0d7b06665a96076f1c561c5f4','4ad80ed7308bde63d6fd89da9846473b42664781']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.699492c9c4000b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
