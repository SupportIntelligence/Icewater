import "hash"

rule m3e9_150a3ab9d9927392
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.150a3ab9d9927392"
     cluster="m3e9.150a3ab9d9927392"
     cluster_size="513 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['03a0043bbe13fdc0a507820f0a114b80', '03a0043bbe13fdc0a507820f0a114b80', 'beb476cd7f29879e74c26cbab5eee4cf']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(108544,1071) == "698123b4097303620115637265df5a66"
}

