import "hash"

rule m3e9_6a5ea44f6452d2d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6a5ea44f6452d2d2"
     cluster="m3e9.6a5ea44f6452d2d2"
     cluster_size="826 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b84dd5b28006913298c57080afea6fa6', 'bb80ec25b6ae07e3c1044248ae1faee2', '2522d8d8eaa7a147cb21d6e27658578a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(138240,1127) == "fddcc1b26534ac99f2294c97171db142"
}

