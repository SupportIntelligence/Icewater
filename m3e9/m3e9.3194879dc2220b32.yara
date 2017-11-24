
rule m3e9_3194879dc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3194879dc2220b32"
     cluster="m3e9.3194879dc2220b32"
     cluster_size="188"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys jorik"
     md5_hashes="['0099f055e3d2f007e1d99118658821e9','01a22d2142b24bf941f81257799b3371','4f99429b96bc76bb49a5670eeab14fbf']"

   strings:
      $hex_string = { 7850c9d6ecca446c8c7c7b56801e0c3207298cafa3a3a4008aafa6ad61709b401ccc00000000000000000000000031e14f78c9d5fbdde0e5c5ea101c21231d34 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
