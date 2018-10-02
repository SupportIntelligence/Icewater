
rule p26bb_2b0f1ac1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.2b0f1ac1c4000912"
     cluster="p26bb.2b0f1ac1c4000912"
     cluster_size="42"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mdeclass bscope cmrtazq"
     md5_hashes="['689e00f0b53da89d260c63b4f68996862a34489f','dc4a02ebe023060e87e4951564af014cb06bf3d6','500c2921d956d7f79bb0214f2957eb8f5ccf9fc3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.2b0f1ac1c4000912"

   strings:
      $hex_string = { 03f845463bf372dc518b4c24142b3156e8677beeff85ed740a8b4424148938b001eb0232c05f5e5d5b5959c3b8ae9b7200e8885a1a0083ec1056578bf98d7708 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
