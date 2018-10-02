
rule k2319_2904a6d5d12bdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2904a6d5d12bdb12"
     cluster="k2319.2904a6d5d12bdb12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik plugin script"
     md5_hashes="['47c9b9c580eb50b95c2b87501591fa4895f11f65','a35577ebb7185314cc29ca150eb9d3135d3dbdbb','08827d73bea6e108a7428d4d456e964d485c293a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2904a6d5d12bdb12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
