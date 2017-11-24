
rule m2321_331db099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.331db099c2200b12"
     cluster="m2321.331db099c2200b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['09941266e423f7755df5c1ae0ce37fc8','5c577ea2c2f747f09e0fae524bc04d45','993cef97eda994a5b47cb6c892821593']"

   strings:
      $hex_string = { 0300cea74f3601e645b48297d6f583550df9e81b526aa621eac69518edb1d2b68012bc72687c4bf074470acd9863fa376e43cba3235d6f784206819f4490777f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
