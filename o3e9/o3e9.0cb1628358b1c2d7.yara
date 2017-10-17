import "hash"

rule o3e9_0cb1628358b1c2d7
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0cb1628358b1c2d7"
     cluster="o3e9.0cb1628358b1c2d7"
     cluster_size="2751 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['043a624047d5467a43c816cf0c22cd06', '03c63feeb7479d4aaede6e9034295bc9', '044b428de46e76bd71e5bc7c42b59be2']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2502144,1024) == "6701c4e8089c8530c355080982e8d63c"
}

