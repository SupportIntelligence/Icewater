import "hash"

rule n3e7_311b1499c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.311b1499c2200b12"
     cluster="n3e7.311b1499c2200b12"
     cluster_size="311 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy qjwmonkey qiwmonk"
     md5_hashes="['12d5fb6c4325aa0ebafa1233b1d86e67', 'c17cd2e5679281bd58343518c86c786b', 'e6a9390f79cab2c547b9857527ec2e51']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(84992,1024) == "cf2c5a2698ac4e34f331971ea711123b"
}

