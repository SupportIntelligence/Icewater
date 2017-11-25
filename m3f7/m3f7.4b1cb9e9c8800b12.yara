
rule m3f7_4b1cb9e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4b1cb9e9c8800b12"
     cluster="m3f7.4b1cb9e9c8800b12"
     cluster_size="120"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker html script"
     md5_hashes="['08bbc1dc27bb421f9efc51ffb46875c8','095aa1ba133e0087da98fc8d2c62f60d','2930c122216d40b488f40cbc921e1321']"

   strings:
      $hex_string = { 31466b556775515173443949546d443745435a494a5345344f5a6f3973746f566a432f7a63376b792b7a483968587756774470544157574c7267533351416538 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
