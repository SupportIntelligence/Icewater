import "hash"

rule n3f9_1d52c6bbc6200b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f9.1d52c6bbc6200b32"
     cluster="n3f9.1d52c6bbc6200b32"
     cluster_size="479 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="srneidlib autorun cobra"
     md5_hashes="['bbaab39d5988fa553b279b6d09db4699', '676142313d2e2d07e59f33b61f166f30', 'cd199d75559a64ff91502fdc981ad0e8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(74752,1024) == "f1f56132cbbdecd22ff394be951bd4b0"
}

