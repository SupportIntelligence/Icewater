import "hash"

rule m3e9_40d26949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.40d26949c0000912"
     cluster="m3e9.40d26949c0000912"
     cluster_size="707 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['4163b14ca14ad533871b8c232bf6a2ea', '6ca7d47fe01b41b30f58fc0e9b4ee262', '6226e9a1dda5a74f57f408e1edcf056c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(20904,1046) == "5b0bd4d16860f26b77f31f4375d198f2"
}

