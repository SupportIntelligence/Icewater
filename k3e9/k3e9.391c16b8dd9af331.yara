import "hash"

rule k3e9_391c16b8dd9af331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8dd9af331"
     cluster="k3e9.391c16b8dd9af331"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['431f8fa77944a8d7727c959be8fc19f2', '4d38ee848c64ec6cf2335bbe9a43d77c', 'b88af3981cb9f7cd2cd46359b1db137b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17920,1024) == "ce1d6e0c4876c0aef8153d7da8e109bc"
}

