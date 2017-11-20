
rule m2321_1b5cc868d912b912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1b5cc868d912b912"
     cluster="m2321.1b5cc868d912b912"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="carberp shiz kazy"
     md5_hashes="['02c166b96b6bba0df9f10ee4d5710b87','617a358080d41dee66d0c9c4fd7b4568','fe7899b24d4d8ede370cf0af3d483021']"

   strings:
      $hex_string = { 214b290ebf80f719cb6625dfbea7ca69337ebd35ce9da9b3d755f8537be46343858358883a0b93b73c55edd4c34dd502622a4c2227901fc4d9c90756bb896416 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
