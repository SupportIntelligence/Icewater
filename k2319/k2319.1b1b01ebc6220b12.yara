
rule k2319_1b1b01ebc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1b1b01ebc6220b12"
     cluster="k2319.1b1b01ebc6220b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5a80616afa286d4f8af58ef489e4964db0a6c041','de5a7006adcbb08a23de49e8c6f9b966174d2c56','4b426a80454d34e7284f2c12d24b3f571640eaa9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1b1b01ebc6220b12"

   strings:
      $hex_string = { 3078313534292929627265616b7d3b666f72287661722051386d20696e206e3643386d297b69662851386d2e6c656e6774683d3d3d2828312e34303945332c32 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
