
rule m3e9_09169039db327b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.09169039db327b36"
     cluster="m3e9.09169039db327b36"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar virtob shyape"
     md5_hashes="['07f7f627eba7a993fafc9ab8bba1d704','137c38d9f65c8ae35379ebe4117ead01','cfde134e0b3ce22f653ecd95da94ff4f']"

   strings:
      $hex_string = { 8edb4808384b94491172f687a1050ec858cb2013861b020b0fdfd3be8974abf553a5391e264565756bd1b1ad92951266a6b59ebdd2ebc10d8c3647ec44604c64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
