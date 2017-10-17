import "hash"

rule n3eb_139da2c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3eb.139da2c9c8000b32"
     cluster="n3eb.139da2c9c8000b32"
     cluster_size="888 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     md5_hashes="['03478ea5cb58ac09ad3e18a8b48d59aa', '399aa2f60b419ab44e09992b3bdbd1fb', '366c5c606df266636eb1ae15f87d7132']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(346112,1024) == "1dae6e829959196fb5c833314f72c51e"
}

