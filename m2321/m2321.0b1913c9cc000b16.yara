
rule m2321_0b1913c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b1913c9cc000b16"
     cluster="m2321.0b1913c9cc000b16"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy shodi virut"
     md5_hashes="['1acc506b404f64977a923cdfd6271a2e','1dad6944c8004ef297d73f807412ff0d','86cd05f00e6238fb234a444ac8e10bf0']"

   strings:
      $hex_string = { 03adc52f6b3772aa265609fa76bdf3688a424428e981afd16fd9110190d8997c934b1306bf9ffc86f9078b5bf0ef0f496087c0dbe00d97585d9885430b461e61 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
