
rule m3e9_297c56d1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c56d1cc000932"
     cluster="m3e9.297c56d1cc000932"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="madangel virut small"
     md5_hashes="['4a92e6d42a8c96c663703bd22e7040ae','6891598cc18b6b79d3c697d5f3f3328e','e20392b6fd7eb51ad9c4cb3bf9164040']"

   strings:
      $hex_string = { fcf3a461c9c2040078037901ebb912000000ba433a5c00515254ff561483f802720b83f805740654e8e20000005a4280fa5a740459e2e0c3c378037901eb33ff }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
