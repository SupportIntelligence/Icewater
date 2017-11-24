
rule o2321_219d10b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.219d10b9c8800b32"
     cluster="o2321.219d10b9c8800b32"
     cluster_size="39"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="miniduke backdoor cosmicduke"
     md5_hashes="['05bc5a21f31659cb624b6c2a9848b434','061b883e70ba7c7796d61048af7b708a','6c426b09a88dcf896fea7ab2b11a3195']"

   strings:
      $hex_string = { 4c130c2b4ea1e01f9d9cf4feaf59bc3353bf78e38ca0d8a64538ebb6862f901c04b87687a56bc7ecf10f8ea302b7df47511b49970d15de816d09c23f799afbba }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
