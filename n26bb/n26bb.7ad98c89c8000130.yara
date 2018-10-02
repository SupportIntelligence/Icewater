
rule n26bb_7ad98c89c8000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.7ad98c89c8000130"
     cluster="n26bb.7ad98c89c8000130"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik bunitu dangerousobject"
     md5_hashes="['28589ff4b2cad5ebcfb2e3edf8d50e095f7ee34d','30297ca5ab6a868f80a4918c5e612eb95a2c110c','2e32856f2144d9630b6bb2225965bf9b126540d4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.7ad98c89c8000130"

   strings:
      $hex_string = { 8469a76400001c8849aaa77600001c886689a75520001d8bde8e9e3820001d8e3be8833e10001d8f3bebb33f20001b8effebbefe200018bbed8b8dfc100001cb }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
