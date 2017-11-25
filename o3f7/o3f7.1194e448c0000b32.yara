
rule o3f7_1194e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f7.1194e448c0000b32"
     cluster="o3f7.1194e448c0000b32"
     cluster_size="109"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker html"
     md5_hashes="['01e7047d4f151c3c9e18e41ed887dd5a','02002276ec0fa41364d50de5c1a9244a','1b8cb81ef3631c107c20037fc2d99bd6']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3927292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
