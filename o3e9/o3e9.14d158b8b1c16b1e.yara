import "hash"

rule o3e9_14d158b8b1c16b1e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.14d158b8b1c16b1e"
     cluster="o3e9.14d158b8b1c16b1e"
     cluster_size="1243 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['3952576674f170c9f4a7c1429020c00a', '13e659e658c267a960b5e8479e0176f7', '446202ef0dc10284a107111b462e29a0']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2963456,1024) == "702e8830efa41008eda2d67c35c035fb"
}

