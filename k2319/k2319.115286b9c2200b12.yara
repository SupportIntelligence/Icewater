
rule k2319_115286b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.115286b9c2200b12"
     cluster="k2319.115286b9c2200b12"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ae9da1de4c379908cad87b9a263537f859a52031','a9c9d4e912c8d0f0cd7c723470b95291ead07dc6','f491c43754d0e6b43440df629c8ae31cc2064036']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.115286b9c2200b12"

   strings:
      $hex_string = { 3a2830783233342c31302e384532292929627265616b7d3b7661722054325236753d7b2752304d273a226e73222c27483675273a66756e6374696f6e28512c4b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
