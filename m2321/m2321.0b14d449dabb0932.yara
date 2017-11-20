
rule m2321_0b14d449dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b14d449dabb0932"
     cluster="m2321.0b14d449dabb0932"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis hafen mikey"
     md5_hashes="['1e1984c501dcb3c90f540527dfe11f15','2eb0d92bd1fecb4aedc481a129d4f601','58176e7c9727f8d8d7b8d61dfbafa6e3']"

   strings:
      $hex_string = { 97eb7d856abe0b98d2ca9571d1fa1a50a5d7cf55ae70ed8d2dba7e4a0cafdac8805c617c14ad9d0adce7e3272f60b44e8c16e87ff7a4f28e04916deabd1882bf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
