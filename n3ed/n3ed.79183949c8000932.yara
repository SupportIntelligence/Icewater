import "hash"

rule n3ed_79183949c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.79183949c8000932"
     cluster="n3ed.79183949c8000932"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['af6b57de20bbf686031bc0132cd03c4b', 'af6b57de20bbf686031bc0132cd03c4b', 'a58a979ca3d95b02818f446b2c45b4a5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(73728,1024) == "d8b3e446ad7fc1eeab8a639744aaa5fd"
}

