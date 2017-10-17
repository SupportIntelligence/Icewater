import "hash"

rule k3e9_624e25513b2a46b6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.624e25513b2a46b6"
     cluster="k3e9.624e25513b2a46b6"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbna chinky vobfus"
     md5_hashes="['a2583e5d7eef6af5a15f9520f117e0b9', 'a2583e5d7eef6af5a15f9520f117e0b9', 'a43af3d5a0335bc8e8b5d04b13f5a8c1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(33792,1024) == "62d12b8e3f7c98fabbc5f8c0f7fc5db4"
}

