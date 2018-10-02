
rule k26bb_291a5548dcb31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.291a5548dcb31932"
     cluster="k26bb.291a5548dcb31932"
     cluster_size="47"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="remoteadmin winvnc riskware"
     md5_hashes="['7c163a5874d01d6061fe8d220900f27eb6d5b13c','562acab4caba92b13403b90ec64b6b8dbcb91bfa','0aa59432d04c79139b378e7e7b5ffdfdd8ac9922']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.291a5548dcb31932"

   strings:
      $hex_string = { 5b72028bc7508753dd1ac5cc0d0c36d901e0c38017b8ee2bf860ec11276a1ce8495973dcfa8d5633d23bda89fd74297d69db54f0920afb8d4ba783c005d09e6c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
