
rule ofc8_739721d4dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.739721d4dec30912"
     cluster="ofc8.739721d4dec30912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['6ad9bd6b383292aab2dd1b0ec3267cb88097d9c6','ca04cfe6ffd3f36202ea60db8839e884485754f6','d5b69b81523ba828faed19e3d82e7b316b317c4a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.739721d4dec30912"

   strings:
      $hex_string = { 3ac1058810847900c46e260f149329113044832f15687ec7b87ce365deafac0d7d5eadbac3ebd570a83e2a736de8fe013125f0ff6b80dd540b34049cb3c6431a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
