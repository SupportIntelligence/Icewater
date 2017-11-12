import "hash"

rule m3e9_71b05cc3cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.71b05cc3cc000932"
     cluster="m3e9.71b05cc3cc000932"
     cluster_size="66 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['395161202be9fa4d4c3a7f962491bd7f', '73ec98d5d55c6399868d9237dcd492a3', 'e59143c23fe4640ad74b8dac6681fafc']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(53248,1024) == "156b6599d3e1a3cb3c196a1448a86364"
}

