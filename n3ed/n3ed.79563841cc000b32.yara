import "hash"

rule n3ed_79563841cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.79563841cc000b32"
     cluster="n3ed.79563841cc000b32"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['84f7835e1bab9bdc1ce6e0add5493f8a', '2e9aa05b116d228cac9854255d12698d', '2e9aa05b116d228cac9854255d12698d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(73728,1024) == "d8b3e446ad7fc1eeab8a639744aaa5fd"
}

