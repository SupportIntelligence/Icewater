
rule n3e9_1b633cc1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b633cc1c4000912"
     cluster="n3e9.1b633cc1c4000912"
     cluster_size="41"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa vilsel chydo"
     md5_hashes="['0a8b4ab60ecd36bbc9e0aad49b543828','2f938695d7c9c47b8a9757ee948b5e9c','b19497abd77596cfe0eeb4ffc9e9d6c4']"

   strings:
      $hex_string = { eee081421440e3b3ffbb8325d565a391437e526924b00d159cbe6ca1d305d650b70a11de94ccec3051a7b5702fd4c2452c713dda7bc1563a5df9731f5923abd8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
