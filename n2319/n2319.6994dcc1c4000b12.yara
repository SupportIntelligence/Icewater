
rule n2319_6994dcc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994dcc1c4000b12"
     cluster="n2319.6994dcc1c4000b12"
     cluster_size="124"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['b160e378c1a3e2bbba7fbf7a073d00dd9030e9fc','ee49ad15171ee92ae16694c15222196586d1e35b','7d0d5d9b039e5fef1f9ae1e03c813f994f46e667']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994dcc1c4000b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
