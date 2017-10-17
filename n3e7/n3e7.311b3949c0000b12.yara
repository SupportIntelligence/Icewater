import "hash"

rule n3e7_311b3949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.311b3949c0000b12"
     cluster="n3e7.311b3949c0000b12"
     cluster_size="57 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy qjwmonkey qiwmonk"
     md5_hashes="['06ddb75f2eaeffe55d4054f742ae5289', '71e2ee37be6733675e378296dea73be2', '8d7e7b6b0caa1c11f31299db3b78ec50']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(84992,1024) == "cf2c5a2698ac4e34f331971ea711123b"
}

