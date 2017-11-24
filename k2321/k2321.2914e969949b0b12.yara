
rule k2321_2914e969949b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914e969949b0b12"
     cluster="k2321.2914e969949b0b12"
     cluster_size="45"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['054204a134d57ea77d8fc4504c862167','0729c2a827c99890638fd4c6de0ceb45','4d3688638a5408c5cdd60fc67c6e549c']"

   strings:
      $hex_string = { 9dafbd76fce85187dd66b1588e1d3d06e67df0fe7bed7c5ec962715928d9852456222c21448b454aa9c45fad421409f6d7614f8c30680d2ad26bb004ec417cca }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
