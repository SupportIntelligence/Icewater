
rule o26bb_4162fcc148000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4162fcc148000912"
     cluster="o26bb.4162fcc148000912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ibryte installer optimum"
     md5_hashes="['68ae456bc8fe8e840c1fb96978c465d4b7e7a2d9','eb4c5c6e84d9d8ded0546ad01c5541cda2446cdc','94013f2af7ed2f0982824d013cbbd3e61112a649']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4162fcc148000912"

   strings:
      $hex_string = { 43107654ceef18b12db96b8f7ff9de93cb14aa80d22bd30397f5e466fdbadfbf26b679a2b7ed575db89bfa25cd1ad7eef7533bff6fa7a4c9b442a934a324952c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
