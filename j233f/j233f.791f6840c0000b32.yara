
rule j233f_791f6840c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j233f.791f6840c0000b32"
     cluster="j233f.791f6840c0000b32"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="voiv script expkit"
     md5_hashes="['d6257c81c6fd6fe6963f4e07e1e19fe408609065','a5f058f27e22684cb30f9885301203c22c3d4514','7fe6fcdbf7c1fc39cf7a3e1210928d91a28affda']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j233f.791f6840c0000b32"

   strings:
      $hex_string = { 002e0030002200200065006e0063006f00640069006e0067003d0022005500540046002d003100360022003f003e000d000a003c005400610073006b00200076 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
