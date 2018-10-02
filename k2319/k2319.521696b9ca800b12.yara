
rule k2319_521696b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.521696b9ca800b12"
     cluster="k2319.521696b9ca800b12"
     cluster_size="74"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['07cd4000c9e95eb732237fb1116437ca2c1afa5e','909aaa213c8adb21393af1c1211463c593430ab3','bab294ca5d3c45e6e6b9171526d4cb6d46f73308']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.521696b9ca800b12"

   strings:
      $hex_string = { 65616b7d3b666f72287661722070327320696e207a34753273297b6966287032732e6c656e6774683d3d3d2830783130333c3d2835362e393045312c35293f27 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
