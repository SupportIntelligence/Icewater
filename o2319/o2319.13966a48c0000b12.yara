
rule o2319_13966a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.13966a48c0000b12"
     cluster="o2319.13966a48c0000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker likejack classic"
     md5_hashes="['d92fa54b6d2135bb10fab4c5e88ecd88f81ecb8d','88ed609161307ae63a80ee802ed9000479253596','0d3f772b33cc96bcf34ccc9396701f1013d1788f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.13966a48c0000b12"

   strings:
      $hex_string = { 5f4556454e542b272e272b414a41585f4e532c205f64657374726f79416a617852657175657374293b0a0909095f6d66704f6e28274265666f72654368616e67 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
