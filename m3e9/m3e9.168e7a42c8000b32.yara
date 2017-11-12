
rule m3e9_168e7a42c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.168e7a42c8000b32"
     cluster="m3e9.168e7a42c8000b32"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbna vobfus chinky"
     md5_hashes="['26dd9ceaacd9487a44c5fc34fa0617bb','29870987eab9a3a3c054a87d93ebbcd1','ba7fbf4242960dc0a4cb032391837c20']"

   strings:
      $hex_string = { 10ff2a3178ff32100030ff2cff24ff28ff18ff1cff0cff10ff1e5807000b6b34fff403c61c4e0300750430fff4012b3aff0577002478000d40070b006c30ff04 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
