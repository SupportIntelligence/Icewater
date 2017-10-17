import "hash"

rule m3e9_2d96cb26ea008932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2d96cb26ea008932"
     cluster="m3e9.2d96cb26ea008932"
     cluster_size="70 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['fcdc07eca29a425fa36c583a6eca23c1', 'cb0bcea31a022d7ee45e76156e4b1ae9', 'a48a10d92f106c446ba9cb2020e786b6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "d0d038130aeb82cf87189ddf5ec47c53"
}

