
rule j2328_0dca652e45aaed32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2328.0dca652e45aaed32"
     cluster="j2328.0dca652e45aaed32"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script exploit html"
     md5_hashes="['495d70e7bf4d56fe7b16c5fe50a0323b2d632bbd','dfef18548a402da9a14d39fcc975aab2e39236b1','d3988624d9d8c5d3faf9bfdb30d3bc42562f5b33']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2328.0dca652e45aaed32"

   strings:
      $hex_string = { 6465736372697074696f6e3e3c215b43444154415b323031382d30332d32392020e5b9bce7a89ae59c92e88889e8bea6e6ad8ce594b1e6af94e8b3bdefbc8ce9 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
