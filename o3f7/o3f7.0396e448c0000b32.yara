
rule o3f7_0396e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f7.0396e448c0000b32"
     cluster="o3f7.0396e448c0000b32"
     cluster_size="142"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['0400921a8006427a835b1ac12e1a1f30','04560eaf978ca3ca4143212adc85441c','22b9f955aa38177e1172e9a62a1a0685']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3927292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
