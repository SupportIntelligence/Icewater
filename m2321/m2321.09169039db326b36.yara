
rule m2321_09169039db326b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.09169039db326b36"
     cluster="m2321.09169039db326b36"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar virtob shyape"
     md5_hashes="['152402694d6fc9e124746ce2857eba2f','24c0d1c52044b83918e3384a6f21ba09','f034ecc6ecfa957413fefd1ea1da3fa1']"

   strings:
      $hex_string = { 8edb4808384b94491172f687a1050ec858cb2013861b020b0fdfd3be8974abf553a5391e264565756bd1b1ad92951266a6b59ebdd2ebc10d8c3647ec44604c64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
