import "hash"

rule n3e9_19904a69c8800912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.19904a69c8800912"
     cluster="n3e9.19904a69c8800912"
     cluster_size="336 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom btcware adload"
     md5_hashes="['50d168eea3b518191de4b0a12be36432', 'd9e3b9a5a9ffe69173c972c07ac07850', '5d094d4a5bf2bae49fe0f9afa7f5edf2']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(400896,1024) == "1e3b32078193678b732190bd3a0659b0"
}

