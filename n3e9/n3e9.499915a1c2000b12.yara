import "hash"

rule n3e9_499915a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499915a1c2000b12"
     cluster="n3e9.499915a1c2000b12"
     cluster_size="164 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="immonitor adagent adspy"
     md5_hashes="['d857385370415f4de0beabd1749a0d9e', 'dcd8e93f34ede82c107e202d50eaaade', '853cdf487ea7bef9a9fbfd5db0b4e9dd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(16414,1026) == "243b669c3c33df21d11cc7d8d5d06bdc"
}

