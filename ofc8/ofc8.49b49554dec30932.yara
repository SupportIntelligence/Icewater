
rule ofc8_49b49554dec30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.49b49554dec30932"
     cluster="ofc8.49b49554dec30932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['e0b077f93892e36548e2a243c98d27897d89729b','fb98efa0ccd9e10d8182f198ea936aab567169e8','a8e3ecd5cb79977b0753fa83aa10c6a44ac7a394']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.49b49554dec30932"

   strings:
      $hex_string = { 30ced0f7a35cfa93e3559a7c13c8ef1007deeccd7b965892fb69000ca553e124c18678c63de5df042fcb9d7a50dc9b1c017f02672e656e270dc0db8e423a0e18 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
