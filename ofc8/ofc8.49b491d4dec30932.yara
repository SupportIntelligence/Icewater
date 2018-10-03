
rule ofc8_49b491d4dec30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.49b491d4dec30932"
     cluster="ofc8.49b491d4dec30932"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['6c4141022de79dfdccd30b9a9723b38638b2923d','c71678ae1e972085359c2d368408716572c649c6','818a907c49d1b533fc1471b34d4001ad3ba4d98b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.49b491d4dec30932"

   strings:
      $hex_string = { 3ac1058810847900c46e260f149329113044832f15687ec7b87ce365deafac0d7d5eadbac3ebd570a83e2a736de8fe013125f0ff6b80dd540b34049cb3c6431a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
