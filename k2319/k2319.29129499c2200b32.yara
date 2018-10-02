
rule k2319_29129499c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29129499c2200b32"
     cluster="k2319.29129499c2200b32"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['695df0cdd706030a390a84c7f1539617454d2f86','1b9f89ec707bcd0f16f4bc7c7aab7a24c5ff06c4','cff30c89c7015145a9a2f13a45fc701b8015dd69']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29129499c2200b32"

   strings:
      $hex_string = { 3245323f38333a28307845312c3078313730292929627265616b7d3b666f72287661722059385220696e206d33563852297b6966285938522e6c656e6774683d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
