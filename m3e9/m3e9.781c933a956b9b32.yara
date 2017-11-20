
rule m3e9_781c933a956b9b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.781c933a956b9b32"
     cluster="m3e9.781c933a956b9b32"
     cluster_size="508"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky vbkrypt"
     md5_hashes="['024a957ae064c0e08518d13599899351','027b38da7874325ede9e9a5d1e0c954e','1b30cc88c3a5009958753edb259d2243']"

   strings:
      $hex_string = { c3dbe27d0e6a44683c6d40005650e83dc9fdff8b75cc8d45d0508d45d4506a02e839cafdff83c40c663bf77f076a015803f0ebf468ab704200eb21f645fc0474 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
