
rule m2377_519b3949c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.519b3949c8000b32"
     cluster="m2377.519b3949c8000b32"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0d2ce8e91dd99f5c22c6f1fbe328247f','10dbff010769ad138b11b1e4d6156c64','cd63bb0a4251cb0701d51f47ef49275e']"

   strings:
      $hex_string = { 0be5110a2b71902f91b44e91fcc9e87fb78b8a848de460d08e13c064bdcdf6d7e9433723a9152afb86dfe87667953fffda0c5317e3d1c3e1b9633e724b47ecfa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
