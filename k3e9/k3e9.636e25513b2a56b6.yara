import "hash"

rule k3e9_636e25513b2a56b6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.636e25513b2a56b6"
     cluster="k3e9.636e25513b2a56b6"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbna chinky vobfus"
     md5_hashes="['768cead999df9f04c06db8bf2bf7a35e', 'aad78090b1fcc5c2f66feb9661a8e2a2', 'bacd2f3ad2710d8af35153fde71b963a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(33792,1024) == "62d12b8e3f7c98fabbc5f8c0f7fc5db4"
}

