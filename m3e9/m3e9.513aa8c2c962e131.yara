import "hash"

rule m3e9_513aa8c2c962e131
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.513aa8c2c962e131"
     cluster="m3e9.513aa8c2c962e131"
     cluster_size="177 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['98589ea6e4885e968fbc2fda77be6711', '01a8d2a3aa1910206d613b6900053a28', '83f662c9583038f7e3a2070c67a62d0d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(169472,1024) == "c64f9367144db1db781024669c374a8d"
}

