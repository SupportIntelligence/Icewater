
rule nfc8_13199369c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.13199369c8800b12"
     cluster="nfc8.13199369c8800b12"
     cluster_size="74"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos origin"
     md5_hashes="['2018f5a693f3967bd727a8a43ae5b0e5380e4675','c343f70776d19076e1380e7da818a38cc63ab688','d99fbaa5fd5a3d52caf50f8681f6edacbd8be8b5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.13199369c8800b12"

   strings:
      $hex_string = { 52deedd6addb5a168be5a7cd892ee6fe0f31bc4d28ae7b4c2cf34ee710ac085e0a57336762993b6577b1267e3dee94a53ef7ff13ba8d4364f03230e80c129fa8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
