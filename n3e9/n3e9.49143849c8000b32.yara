import "hash"

rule n3e9_49143849c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49143849c8000b32"
     cluster="n3e9.49143849c8000b32"
     cluster_size="6352 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="andromeda gamarue injector"
     md5_hashes="['01ff4a540820ac588b4e1aabec51cf74', '02ee55050447b682d36576e0cb99f542', '0082441a21e04ff034ece66fd83534a8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(97280,1024) == "7b31756f04996b91b1f2eef83fe8b231"
}

