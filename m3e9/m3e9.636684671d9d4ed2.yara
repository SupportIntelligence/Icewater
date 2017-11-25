
rule m3e9_636684671d9d4ed2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.636684671d9d4ed2"
     cluster="m3e9.636684671d9d4ed2"
     cluster_size="322"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['006e127f8c46cf4639dd47229ea2630e','012b7584ac77d3d9fd30f8ff12a2f1fd','1107effaaa1992abae376fcc58fb311e']"

   strings:
      $hex_string = { 50ff7508ff15241200018d65c05f5e5bc9c228008b13f6c201b80d11000074dc84d26a0a598bf38d7dd4f3a579068b43288945fc8b431085c075052145e4eb30 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
