
rule k3e9_6ab2d794dad30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6ab2d794dad30912"
     cluster="k3e9.6ab2d794dad30912"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="outbrowse nsis unwanted"
     md5_hashes="['3bfe8ad2eabef9aaf116fff7b5e4ff12','8197fc4f1bec37fc64e0efae4533d971','f09820368c3088bfef1a19e09030b596']"

   strings:
      $hex_string = { 3a0292a5966fa2d9c9d0678436e30b7acf6ad68d1422be8ff10fb02ca08938f56b4610595ed18edd443f5b7e1ada4f16eaa9de1d42d3562e65a63c734730931f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
