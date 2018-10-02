
rule n26d7_3914cce3e9691b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.3914cce3e9691b16"
     cluster="n26d7.3914cce3e9691b16"
     cluster_size="89"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zvuzona zona adload"
     md5_hashes="['000f3a5da9b57c7e7db2b53c7e5313b0e61b0e43','3103b068dcea3dd03c1961ac5b43206a0d2c4d28','77c6e02bfeae71d5cff18a976644f2d829b796b7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.3914cce3e9691b16"

   strings:
      $hex_string = { d00fb70183c10203c281f946be45007ce989450c8d550c8bc6e88ca9feff8b0085c07505b820be45008b4d085068048e45005351ff15a852450083c4105b5f5e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
