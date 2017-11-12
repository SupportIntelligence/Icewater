import "hash"

rule k3e9_6b66d36f994b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b66d36f994b5912"
     cluster="k3e9.6b66d36f994b5912"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['dfec463cd6e4b6d6a5ef825344ca3738', 'bfcb25fa863f868a11d14a1d2fa75bec', 'b720b1b0886e2a54276b8d7f50ff540c']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(9288,1036) == "2a5ed0a6e568c6168dc9cdc440a1598c"
}

