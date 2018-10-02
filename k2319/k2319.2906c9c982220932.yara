
rule k2319_2906c9c982220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2906c9c982220932"
     cluster="k2319.2906c9c982220932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['fe80624d8b49555dc745b57950c46d1eccb15879','3fb87571b13908ee2a9bf5559a921be2fd29c676','98857ce3fbcda2dbf27dcec33c37b9a24b82b401']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2906c9c982220932"

   strings:
      $hex_string = { 2e293c3d37373f28307846442c313139293a2830783135422c3930292929627265616b7d3b7661722066335432643d7b274b3664273a66756e6374696f6e2875 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
