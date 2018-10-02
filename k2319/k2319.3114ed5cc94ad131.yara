
rule k2319_3114ed5cc94ad131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3114ed5cc94ad131"
     cluster="k2319.3114ed5cc94ad131"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik plugin script"
     md5_hashes="['afed4b07d8a767dc2cee169755fcc2f45e8ef914','644e60485944de661c28fac96d1d712d4978520a','e321b5192e598234e139b5187cfa43d46ce42eec']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3114ed5cc94ad131"

   strings:
      $hex_string = { 773b666f72287661722063383520696e206b33643835297b6966286338352e6c656e6774683d3d3d282836342e2c3134302e334531293e307843443f28307832 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
