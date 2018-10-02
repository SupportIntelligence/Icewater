
rule k2319_303516b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.303516b9c8800b12"
     cluster="k2319.303516b9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c6c3e4136f26d86cbecbe4f0a26761b727851e02','8339115cf3c066f6ccf60046b990c88ca2257476','2136ba6fdc54282abfd757779dc024b340489270']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.303516b9c8800b12"

   strings:
      $hex_string = { 2e363945322c313139293a28307842332c39332e292929627265616b7d3b76617220503643373d7b277a3170273a2235222c274f37273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
