
rule n414_53354a4a96a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n414.53354a4a96a31912"
     cluster="n414.53354a4a96a31912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy dangerousobject malicious"
     md5_hashes="['a15d50e55bf868404128bf042e9edfa16ae99922','9ee83ede6f45897d774f6748e2482a56759d34e7','a7effafa88cc4945799c961ef3b5c8ed626cf651']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n414.53354a4a96a31912"

   strings:
      $hex_string = { 8d902931778106890f2bdf1412270d711f5121de5b1c38b2a7fe6119bfdeaa3b0c982822363e478cf744cc74f10e8470d6c59e83d1ce579a0509919482e6bba1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
