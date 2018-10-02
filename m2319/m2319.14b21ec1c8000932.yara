
rule m2319_14b21ec1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.14b21ec1c8000932"
     cluster="m2319.14b21ec1c8000932"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['3186aa232f01e79df1498c5f444406f0adcba425','539157c0af9e79ae68c66330f442ac1825d9852f','9e8cb76a5c761d8577d2b8972b111ae7e04011c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.14b21ec1c8000932"

   strings:
      $hex_string = { 3e3c6272202f3e0a0a0a3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
