
rule k2319_69341eb9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.69341eb9ca800b32"
     cluster="k2319.69341eb9ca800b32"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4a1f16481495ce75c5fbad665ba959d14806d624','ab6aeaff94edc567fd5846688e9729529e45878f','5f9d623ceb2df1d1da745d9f2dbec2dbca102584']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.69341eb9ca800b32"

   strings:
      $hex_string = { 362e3f2830783139342c31302e33394532293a283078452c3078313231292929627265616b7d3b7661722058374638313d7b27453331273a2866756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
