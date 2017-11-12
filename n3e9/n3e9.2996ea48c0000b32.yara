import "hash"

rule n3e9_2996ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2996ea48c0000b32"
     cluster="n3e9.2996ea48c0000b32"
     cluster_size="52354 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="urelas symmi gupboot"
     md5_hashes="['0049be041f816a56d8aa0af7f0e64850', '02132e32be0d031171f1e2bb2086e084', '028f72c323fd81ee6916df23565897d9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(133120,1024) == "6ac1e36c1b4fdc28e7de6678651a98fb"
}

