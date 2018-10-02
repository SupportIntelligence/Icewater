
rule n2319_2b1a3ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.2b1a3ec1c8000b12"
     cluster="n2319.2b1a3ec1c8000b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['44f2251215722c7caad3b9ecdb405543ee24e791','9478ad20d14d4c4afbe9be8beb1b815b67cc0381','56765c9c879bc321c2feb2f621391bdf926cb43e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.2b1a3ec1c8000b12"

   strings:
      $hex_string = { 626f784d6f64656c3b76617220693d2f5e283f3a5c7b2e2a5c7d7c5c5b2e2a5c5d29242f2c6a3d2f285b412d5a5d292f673b662e657874656e64287b63616368 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
