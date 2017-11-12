import "hash"

rule n3e9_49143849c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49143849c8000b32"
     cluster="n3e9.49143849c8000b32"
     cluster_size="16299 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="andromeda gamarue injector"
     md5_hashes="['0e5961137bd80279ce3ae1c1d31cf702', '10c5b4e5f59396f6ec71a7ed7d3997e2', '0b3d1a1872628c929f07cef20bc1cda8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(97280,1024) == "7b31756f04996b91b1f2eef83fe8b231"
}

