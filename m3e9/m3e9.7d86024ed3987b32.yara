
rule m3e9_7d86024ed3987b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7d86024ed3987b32"
     cluster="m3e9.7d86024ed3987b32"
     cluster_size="86"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chinky vobfus vbkrypt"
     md5_hashes="['0a6c590b9b3741bae45769e294359249','0f4a993c0cdb08b130183e253d408b5d','a1f45e29c3e29ba92b972a8fc53163a7']"

   strings:
      $hex_string = { c3dbe27d0e6a4468e07e40005650e81997fdff8b75cc8d45d0508d45d4506a02e81598fdff83c40c663bf77f076a015803f0ebf4683fa44200eb21f645fc0474 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
