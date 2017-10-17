import "hash"

rule n3e9_33967694d7bb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.33967694d7bb1912"
     cluster="n3e9.33967694d7bb1912"
     cluster_size="46 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="foax kryptik malicious"
     md5_hashes="['c6a297e6d04af8528811b1da38170954', 'c6a297e6d04af8528811b1da38170954', 'd537e1159d68f6150db0a337d5e6ec8e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(709632,1024) == "8d21882e41bdacd12db6f0615f57dabc"
}

