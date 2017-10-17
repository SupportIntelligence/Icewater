import "hash"

rule n3ed_7914e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.7914e448c0000b12"
     cluster="n3ed.7914e448c0000b12"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['5aa1df9b8fb62c375f83c1efaec473d7', '0fda97b9b356bc67eb3f1e2ace7e147c', '5aa1df9b8fb62c375f83c1efaec473d7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(73728,1024) == "d8b3e446ad7fc1eeab8a639744aaa5fd"
}

