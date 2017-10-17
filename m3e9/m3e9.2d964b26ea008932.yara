import "hash"

rule m3e9_2d964b26ea008932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2d964b26ea008932"
     cluster="m3e9.2d964b26ea008932"
     cluster_size="151 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['efdfb0a48c4df74dffb4966b08e6cbfb', 'e7564ccb204044d6d0406fef765dae14', 'ac19a554a5055e585f622bce7a5f61ba']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "d0d038130aeb82cf87189ddf5ec47c53"
}

