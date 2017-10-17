import "hash"

rule o3e9_49324292dde98912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.49324292dde98912"
     cluster="o3e9.49324292dde98912"
     cluster_size="4514 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="blackv noobyprotect malicious"
     md5_hashes="['00af32931d099ab50f460b658b927187', '0727486d3165bd62d6d36120b2991bf2', '0a224619160f12f24b5981c1c8411b43']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3093504,1024) == "cf92365a5b8f1a2d111aa0c2629881e7"
}

