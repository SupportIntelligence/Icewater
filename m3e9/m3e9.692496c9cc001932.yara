
rule m3e9_692496c9cc001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692496c9cc001932"
     cluster="m3e9.692496c9cc001932"
     cluster_size="2240"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['008e9c26ea97e5c7c31aadc7c6f3f546','009d4a0565b862e42c91c7da580b4c32','04ffb9dd3ebb39a12577cb51f0587458']"

   strings:
      $hex_string = { d2d0bec3c6caccd1d5db50510316e7ef13f6f6148ce1e0fafdfcf7ee0454e3e30b586a6a7a7f77747d7d870ff408080808d6bdc3c8cacdd4d7dadd50eceb8def }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
