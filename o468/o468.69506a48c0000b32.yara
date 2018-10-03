
rule o468_69506a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o468.69506a48c0000b32"
     cluster="o468.69506a48c0000b32"
     cluster_size="108"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="expiro allinone classic"
     md5_hashes="['b411dec84ed4aada0057235a5406e5b3b3bd6724','34377f5b6cf5d94ccb043754da3f63ff2b74e30d','0b01166a8f4f7cf1589ed277114f2e744d5b4877']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o468.69506a48c0000b32"

   strings:
      $hex_string = { 446f8387953b3682397412d66b8ea414cc9176af397e135316190b213d1cf558bd1bc5c108b03f5f7f11d50a3a146a3ee3eba470f2e03cf2377bc9a96cb4e88f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
