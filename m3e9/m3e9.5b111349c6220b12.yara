
rule m3e9_5b111349c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5b111349c6220b12"
     cluster="m3e9.5b111349c6220b12"
     cluster_size="45"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd ircbot diple"
     md5_hashes="['0097a2f1c9b6b4d8c77f5a7939cf4d46','0a3d994af11098236f1a76f2222be392','5e464ab9fcb476e18bf15f886951fc1b']"

   strings:
      $hex_string = { a46810ba4a74a8ae563a3d2170841672d4b84fbed8fab3fcf30a7c506d098066a34865711144de83f855a19a1c32d0eaedf6e7952425d1b945e7e90b3e1263c8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
