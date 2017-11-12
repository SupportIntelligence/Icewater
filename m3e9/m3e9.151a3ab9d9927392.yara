import "hash"

rule m3e9_151a3ab9d9927392
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.151a3ab9d9927392"
     cluster="m3e9.151a3ab9d9927392"
     cluster_size="727 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ad8d3d837675355de3fbc170d4422ab7', '1c532b8f8bef6a0f536a39919f9933fb', '0636c6b634e6e41e0b05bb3ec6394564']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(108544,1071) == "698123b4097303620115637265df5a66"
}

