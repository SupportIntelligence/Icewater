import "hash"

rule o3ed_131a9d99d68b0916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9d99d68b0916"
     cluster="o3ed.131a9d99d68b0916"
     cluster_size="6204 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['387afcde7bf8ddce59db167424bd442f', '084b5385af755f49bb307760bfe0f2b5', '2da00bf143f5e29a6dd9bc708e792a68']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2137088,1024) == "ff5f1f7c34de76a2ed3703a11514ea4f"
}

