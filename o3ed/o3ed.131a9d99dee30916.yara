import "hash"

rule o3ed_131a9d99dee30916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9d99dee30916"
     cluster="o3ed.131a9d99dee30916"
     cluster_size="2061 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['246e4ca37f1383dd9e3996b3ed793e57', '52ddbf3726eec7e93b9d5c29f8b81ad1', '60bc1327ce74e9e0720a3723954624fa']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2137088,1024) == "ff5f1f7c34de76a2ed3703a11514ea4f"
}

