import "hash"

rule n3ed_791e3ac1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.791e3ac1cc000b32"
     cluster="n3ed.791e3ac1cc000b32"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['da96a77253b8fd74c1fc5968c1223b71', 'a1010b81a0238e310274322a968d77bf', 'bb6f96dea715f0d7f3223621a275723e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(73728,1024) == "d8b3e446ad7fc1eeab8a639744aaa5fd"
}

