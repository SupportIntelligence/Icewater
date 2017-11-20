
rule m3e9_29d4ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29d4ea48c0000b32"
     cluster="m3e9.29d4ea48c0000b32"
     cluster_size="97"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="madangel small madang"
     md5_hashes="['0d870fe19c872e20267b1e531b7b18e3','10218542546b178a1e81e238611e7959','76a560802b0e61956d65ca7babcd99be']"

   strings:
      $hex_string = { fcf3a461c9c2040078037901ebb912000000ba433a5c00515254ff561483f802720b83f805740654e8e20000005a4280fa5a740459e2e0c3c378037901eb33ff }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
