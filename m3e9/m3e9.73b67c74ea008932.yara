import "hash"

rule m3e9_73b67c74ea008932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73b67c74ea008932"
     cluster="m3e9.73b67c74ea008932"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['6a82e226038261f031aa9ea383cc3335', '834925e1b2b909cc6b74732f68e787d5', '555969736723a3ff6c6440cdc37fd6eb']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(84992,1024) == "967cfe988bc65ab5193f8658032c7ee8"
}

