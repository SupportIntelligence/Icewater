
rule n2319_5916ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.5916ea48c0000b32"
     cluster="n2319.5916ea48c0000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos faceliker script"
     md5_hashes="['5fdc3212a9cd7746d146ef4b88986ea94e56ef06','be712aa7a16db076c9195e7dca8809b023e66391','ac0c57c18ca51f25a83f8e1a646263bc80d83021']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.5916ea48c0000b32"

   strings:
      $hex_string = { 61297b76617220623d7528766f69642030293f22756e646566696e6564222e7265706c616365282f285b2d28295c5b5c5d7b7d2b3f2a2e245c5e7c2c3a233c21 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
