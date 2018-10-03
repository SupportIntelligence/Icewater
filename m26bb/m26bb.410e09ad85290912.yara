
rule m26bb_410e09ad85290912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.410e09ad85290912"
     cluster="m26bb.410e09ad85290912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious vitro"
     md5_hashes="['b146faeb9854116f691db0cdb41594c65ffe5109','14da8cadefa8b8f4f658c7df35493fd66419e2a5','77814205896fdae3f6f6efbd38a9e0b274288b86']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.410e09ad85290912"

   strings:
      $hex_string = { 45085333db568bf185c974268b551057bffeffff7f2bf92bd08d0c3785c9740d8a0c0284c974068808404e75ec5f85f6750648bb7a000780c600005e8bc35b5d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
