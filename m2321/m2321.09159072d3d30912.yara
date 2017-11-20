
rule m2321_09159072d3d30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.09159072d3d30912"
     cluster="m2321.09159072d3d30912"
     cluster_size="73"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['00503b9dff44c1623913335f2e7c703c','01587dc5eb429b75bc05ce58cb572b42','400dea8490eb5b59f4a716951d803bda']"

   strings:
      $hex_string = { f63831e3f7f344898c97180c48581bfb3d2c7511d70f1d1eea5167bd7c79f2bb6caececbfd45f90916ac9286cf0588edbb3cb9c08f0db3ebd99cd49bc51f66e9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
