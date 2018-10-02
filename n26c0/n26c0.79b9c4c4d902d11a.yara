
rule n26c0_79b9c4c4d902d11a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.79b9c4c4d902d11a"
     cluster="n26c0.79b9c4c4d902d11a"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious arre chapak"
     md5_hashes="['5f0748692938c89eb95c27a8ccd07827a19c752b','2d053c6ac4edf430124197e75d2d4bf3dcb5509f','a0a8e863e02ea9f4d950fc408c63aab3efb1ab74']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.79b9c4c4d902d11a"

   strings:
      $hex_string = { baf8c54e005683e01f33f66a20592bc8b8d4c54e00d3ce33c93335705044003bd01bd283e2f783c2094189308d40043bca75f65ec3558bec807d0800752756be }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
