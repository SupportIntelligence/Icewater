
rule n3e9_69147949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.69147949c0000b12"
     cluster="n3e9.69147949c0000b12"
     cluster_size="56843"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi gamarue buzus"
     md5_hashes="['0001bcce2d3027007e2828287f8aa6bf','00045ad721a2d12c39fae46513a58e95','001d1d1c31d95c4c13b84ac15175ba26']"

   strings:
      $hex_string = { 0064002000530043005000200063006c00690065006e0074000000000036000b000100460069006c006500560065007200730069006f006e000000000034002e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
