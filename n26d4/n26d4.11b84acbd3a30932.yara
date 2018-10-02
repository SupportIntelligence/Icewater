
rule n26d4_11b84acbd3a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.11b84acbd3a30932"
     cluster="n26d4.11b84acbd3a30932"
     cluster_size="42"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jaik guildma ransom"
     md5_hashes="['1abec9748085e78bc8cc502421b5363959efc2ef','b45a987f511507d2ef638be069523f10a254c828','8847997be93c694b8873edcd2ec10e4cb2b5291f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.11b84acbd3a30932"

   strings:
      $hex_string = { eb0fe9044dfeffbb03010380e82651feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c0556882ea410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
