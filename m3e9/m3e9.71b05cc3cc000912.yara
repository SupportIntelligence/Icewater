import "hash"

rule m3e9_71b05cc3cc000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.71b05cc3cc000912"
     cluster="m3e9.71b05cc3cc000912"
     cluster_size="397 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['5962e33c920fd1ee867cd74fdffff466', '848b9d66479d33e5467075e0be4042a3', '25ed8487db2d915d8e291f36fb8aa68a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(53248,1024) == "156b6599d3e1a3cb3c196a1448a86364"
}

