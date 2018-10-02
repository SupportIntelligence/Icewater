
rule o26bb_57d2530cce210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.57d2530cce210b12"
     cluster="o26bb.57d2530cce210b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious unsafe unwanted"
     md5_hashes="['6b20262a4c12667bb467cdc965146154cd9b1ad7','a0421c4f3cd7f83fc4ba81f7db04b323fe72a39d','050be7d765ba77960c6761fc528c86ff620ce5f1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.57d2530cce210b12"

   strings:
      $hex_string = { 897c24504c63fd4f8d24bf49c1e7040f2974244049c1e4034983c7084b8b042f4c2bf03bef7d420f57f685ed792133db85ff7e390f1f4400008bd3488bcee8b6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
