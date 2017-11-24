
rule k2321_3914ed68989b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.3914ed68989b0b12"
     cluster="k2321.3914ed68989b0b12"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['074edf282eafde48f32d1c89e5b937ae','095cbaa729c633bd94d3e83c8ba198ca','c42752ef1336f6ed022e762ab70e31fa']"

   strings:
      $hex_string = { 8be5d8d16360de07efbfd7cee7952c169785925d486225c21242b458a4944afcd52a4491607f1df6c40883d6a022bd064bc01ec4a7bc9cec575edc7ef0871f70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
