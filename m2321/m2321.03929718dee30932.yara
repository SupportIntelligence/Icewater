
rule m2321_03929718dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.03929718dee30932"
     cluster="m2321.03929718dee30932"
     cluster_size="10"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['32ae35261c28a9e126832e0c7bc86051','334b7b5d6f96d73c923149be053fc97a','fdcca4788931f30b7a7f2ffa34468bd4']"

   strings:
      $hex_string = { ee2d2ec8bd0585d937ed0177574fdd3a186c545f4def8ae2cbf6e9420cb6d15d66767ce01d4bf822bc67215aba4170d38ec0eb0b2c6fb990c34586c250680d56 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
