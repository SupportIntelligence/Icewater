import "hash"

rule o3e9_09b134a6df4369b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.09b134a6df4369b2"
     cluster="o3e9.09b134a6df4369b2"
     cluster_size="208 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['c1e9ca7588ebc3218f7c653b94790bf6', '935d0f3ac44ab155f9588607e68f8ea4', '3c94141db2426d9e2d57dd41aac30b07']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2714624,1024) == "41da7d8e944031bcefba660f42d0ae09"
}

