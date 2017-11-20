
rule m2321_299d6848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.299d6848c0000b12"
     cluster="m2321.299d6848c0000b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif agentwdcr fixflo"
     md5_hashes="['1a1f74e7080c97b881b6f35b93e1665f','86f51672301c7c48b6b799b746f8ca1b','e25d8b9c567f4bec951deff291985ff0']"

   strings:
      $hex_string = { d5b87a154c6147431e9f89c11a459767038f09792fb9868a8768a68404e6d193e9565ebe9c11faf9ba0d249bc8d19471d7ef82758b1481cda08e3b17c4f8ae5d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
