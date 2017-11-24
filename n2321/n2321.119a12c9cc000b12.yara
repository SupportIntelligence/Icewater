
rule n2321_119a12c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.119a12c9cc000b12"
     cluster="n2321.119a12c9cc000b12"
     cluster_size="159"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="filetour adwaresig dlvh"
     md5_hashes="['00b4fab4fa6a7abee69f2340d7f288ab','00de53cbe761fba9f69efa9ce00fccd3','2427996a2f7599a5eb91f8ca6f7b4afd']"

   strings:
      $hex_string = { 1851a29644badce5f41d0d8011f0c62f3b4641af2722e8daee4e248d19579bd747737cd404d87ce305c5869fa116b99907f270f74a7b52200a2c81536129f364 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
