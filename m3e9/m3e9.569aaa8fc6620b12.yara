import "hash"

rule m3e9_569aaa8fc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.569aaa8fc6620b12"
     cluster="m3e9.569aaa8fc6620b12"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['1175269c3bc276e1c6fbbe9fe4ff79b7', '3636b79c570191be7964135149778acb', 'ab428037d83df9c0b5f6373bc575862a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(25600,1536) == "3fb90aaf37e9d8daab78bc68e1e24bdd"
}

