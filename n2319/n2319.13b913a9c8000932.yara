
rule n2319_13b913a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13b913a9c8000932"
     cluster="n2319.13b913a9c8000932"
     cluster_size="79"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['ca77ff46170a53a2d2129caaa865f7bbedd66460','ee5b1803d746182e851e2932f859880843f07228','5d2040f16a9aa53bd808f364666eb0e1c1090dac']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13b913a9c8000932"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
