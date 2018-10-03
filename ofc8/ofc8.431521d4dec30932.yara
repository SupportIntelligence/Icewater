
rule ofc8_431521d4dec30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.431521d4dec30932"
     cluster="ofc8.431521d4dec30932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['14d5f32a14926b4f170fcdc59f3af982b1bd4d73','04fbec02c86dfb9c90e260bd90ae9ed663279fbe','ce381f0eacc29b26ec830bd8a7b338330262d844']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.431521d4dec30932"

   strings:
      $hex_string = { 3ac1058810847900c46e260f149329113044832f15687ec7b87ce365deafac0d7d5eadbac3ebd570a83e2a736de8fe013125f0ff6b80dd540b34049cb3c6431a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
