
rule j2328_0d5a6d4acfe96932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2328.0d5a6d4acfe96932"
     cluster="j2328.0d5a6d4acfe96932"
     cluster_size="142"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script exploit html"
     md5_hashes="['bfeb51d47369190a7d743bc55391f941e7712371','0ce207735a0f3931986f3cce7759c389640fff89','2efcef97347fe02ab7535d855befb22a43757e33']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2328.0d5a6d4acfe96932"

   strings:
      $hex_string = { 6465736372697074696f6e3e3c215b43444154415b323031382d30332d32392020e5b9bce7a89ae59c92e88889e8bea6e6ad8ce594b1e6af94e8b3bdefbc8ce9 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
