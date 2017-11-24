
rule m2321_1299509222714b66
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1299509222714b66"
     cluster="m2321.1299509222714b66"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="autorun mepaow lamer"
     md5_hashes="['1f58512c7f5ee2e7a5b77b7e1213f53c','8805ed3633076d7c5c0ac5ed1c3dc410','cb20f4174db10a7a32cce932edb39007']"

   strings:
      $hex_string = { bbe8e441a37d7749c99016d139e33d2bb76e033ba45c50730555b84ad9be8783e54bfb6995236d98027e256f275d99deb1f8a097aeb294eb3cda6a099154d09d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
