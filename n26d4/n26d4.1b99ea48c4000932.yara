
rule n26d4_1b99ea48c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1b99ea48c4000932"
     cluster="n26d4.1b99ea48c4000932"
     cluster_size="47"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy extenbro malicious"
     md5_hashes="['26072bfc19d4c3d623c7b003540d5b5ae8066cba','26c3b69464a295cf11085547486d0fbd44c1e35a','039f09dc816a2c8762479821d5255aefce1c5895']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1b99ea48c4000932"

   strings:
      $hex_string = { 0803f8897e348b4e2885c97f068bc30bc27437536a00ff75108d41ff5253894628e8696b0100895dfc5b80c1308bd880f9397e0c8a45143401c0e005040702c8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
