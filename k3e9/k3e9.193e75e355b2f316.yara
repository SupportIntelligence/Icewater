
rule k3e9_193e75e355b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193e75e355b2f316"
     cluster="k3e9.193e75e355b2f316"
     cluster_size="35"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply installcore advml"
     md5_hashes="['0056d1315c5e7e519ac6a67087080f38','017c327773ace5e5d4869f887ed44442','90f3145848c860720af28f9da68cda1c']"

   strings:
      $hex_string = { 7b6cb86e9afe0545f4d3bd2991fba9e404f67743eba373c07aad7d8b4da0dece5cf149dc094c3246614748001f17b222be1b54fc02b4f00c8311e0e54e569d68 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
