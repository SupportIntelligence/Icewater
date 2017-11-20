
rule k2321_491a9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.491a9cc9cc000b12"
     cluster="k2321.491a9cc9cc000b12"
     cluster_size="6"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['19df685c1880c1c8ad45fbdaf0e57698','3b17a65541411c6b70b622335dd00c3a','d7c0a8ef20f2907058d839159a8c05f3']"

   strings:
      $hex_string = { b5987cfa67492a85cf5e8452a5b6188f305cda81959d6ddd331c5687173f4468da832861c0486021baf7f18b138c383ec9ea12d24c017962a93c65c77b1a6341 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
