import "hash"

rule o3e9_1a9308d6969279b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1a9308d6969279b2"
     cluster="o3e9.1a9308d6969279b2"
     cluster_size="785 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonstr installmonster malicious"
     md5_hashes="['4174a056c51020560dcc14038ba5012e', '16ae40462f8359549b6fa1abe814fc36', '445aca83efa4d55c8558902db9b33add']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2587648,1024) == "594f4971d6011e48b525b2f8581226f9"
}

