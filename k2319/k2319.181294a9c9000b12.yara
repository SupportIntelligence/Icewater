
rule k2319_181294a9c9000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181294a9c9000b12"
     cluster="k2319.181294a9c9000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['74e7edf90b67184bafacd1015feda182224019d4','7802e8404bde8cb1ec84e47517a0c073e2b6d2d2','d4a0650b1bc75e85866509e328eb2fd8f7eb9f86']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181294a9c9000b12"

   strings:
      $hex_string = { 39293a28307845462c3131322e292929627265616b7d3b7661722056324e353d7b27563354273a226c65666768222c274639273a66756e6374696f6e28712c41 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
