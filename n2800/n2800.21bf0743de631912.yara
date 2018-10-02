
rule n2800_21bf0743de631912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2800.21bf0743de631912"
     cluster="n2800.21bf0743de631912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer malxmr smstak"
     md5_hashes="['837ef7243cc891849a982d924bb5fd0f3198a066','09940e83551ef358044e22d1f97eb455409d0b01','fb4df0bccc2f5de841797b2617cfe296f3e0b95f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2800.21bf0743de631912"

   strings:
      $hex_string = { c6ffc733ede9990000004d85f6742d448bc74d3bc40f8321010000488bc2c0e206492bc548c1f80242080436498bc548c1e0062ad080e2c043881430ffc6bd03 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
