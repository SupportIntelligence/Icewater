import "hash"

rule o3e9_6b156b49c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6b156b49c0000b16"
     cluster="o3e9.6b156b49c0000b16"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor trojandropper malicious"
     md5_hashes="['96ca8cfe12ad55a326bf3d54afb102ea', 'de88261b73ef5b2bfb607401fe3fd5f5', 'de88261b73ef5b2bfb607401fe3fd5f5']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(12288,1024) == "364f50a36b1937f39df27a37a04c36bc"
}

