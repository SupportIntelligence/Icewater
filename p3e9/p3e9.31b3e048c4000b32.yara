import "hash"

rule p3e9_31b3e048c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.31b3e048c4000b32"
     cluster="p3e9.31b3e048c4000b32"
     cluster_size="802 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['4bb2ded6fcb2f0544d992d6dc55a884f', '33d5d2945f4ee26ccafb1bc2da6fbf9c', '3486efe114cbfc709a6f0e1bd3969862']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(3271183,1025) == "b28fde35cceb540730107b616e88ed9c"
}

