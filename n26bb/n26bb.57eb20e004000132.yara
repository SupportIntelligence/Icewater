
rule n26bb_57eb20e004000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.57eb20e004000132"
     cluster="n26bb.57eb20e004000132"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtob malicious patched"
     md5_hashes="['d1ce0b04db3cffc477d0031321ed29aa3c8a3037','d34bbfbec04dd87261d305819db0e965c566dd35','2bea2fd345c20e0e50830219e02e430e477e21c2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.57eb20e004000132"

   strings:
      $hex_string = { 45085333db568bf185c974268b551057bffeffff7f2bf92bd08d0c3785c9740d8a0c0284c974068808404e75ec5f85f6750648bb7a000780c600005e8bc35b5d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
