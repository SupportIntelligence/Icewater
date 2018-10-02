
rule n26c0_79b9c4d4d992d11a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.79b9c4d4d992d11a"
     cluster="n26c0.79b9c4d4d992d11a"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="chapak malicious arre"
     md5_hashes="['ff540fa989ddc51a8738f2bd5945abce8a3949f6','bcfe015b99637f00aec87d41a94cff474d68b2f3','dba124e02084dad334ea01d475ec654c4cc1bbbb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.79b9c4d4d992d11a"

   strings:
      $hex_string = { baf8c54e005683e01f33f66a20592bc8b8d4c54e00d3ce33c93335705044003bd01bd283e2f783c2094189308d40043bca75f65ec3558bec807d0800752756be }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
