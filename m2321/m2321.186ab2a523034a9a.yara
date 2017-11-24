
rule m2321_186ab2a523034a9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.186ab2a523034a9a"
     cluster="m2321.186ab2a523034a9a"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['0eac549c25e1262888b66175d1fb3117','52214856f8b9c7cacb63017ed085fd1e','e99f36438b685e9d0cb0bcbd827ab89b']"

   strings:
      $hex_string = { 19d1540100f47836aa7646d2500bc375cda25a909d3a561b2b9959e321effb3fc0a4d94d9b9f89c48c03c10ece98be09d7397e0b061d28ec657c68164e49c86b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
