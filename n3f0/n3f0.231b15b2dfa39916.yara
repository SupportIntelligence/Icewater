import "hash"

rule n3f0_231b15b2dfa39916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.231b15b2dfa39916"
     cluster="n3f0.231b15b2dfa39916"
     cluster_size="52 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mira ccpk malicious"
     md5_hashes="['b2cb157b4869091c81a90da128b9de93', 'c16712889cf084869581d77f453285f1', 'b2b1f00a04fe7e4970656498a7a400fa']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(257536,1280) == "50bd3647c518c2cc4b265b800b3315c9"
}

