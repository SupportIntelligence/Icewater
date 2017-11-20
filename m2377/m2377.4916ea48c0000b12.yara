
rule m2377_4916ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.4916ea48c0000b12"
     cluster="m2377.4916ea48c0000b12"
     cluster_size="17"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0c93103f3cd2ff5a8dc6dcb29f020120','0d7fe498be1f2a2d20b110aa54971f0d','ab222270ab8fec2af82feaa2715bffd1']"

   strings:
      $hex_string = { 3487088b57350c0e7a3cf22b38f07c4c45e59cad2adfc2f9af2f11eb67216cdbc8efc1f327f16ab65176d2e790cfa3924474e154834e30b15ea2dcce2d23188c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
