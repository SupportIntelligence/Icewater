import "hash"

rule o3e9_30b3214d6a208932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.30b3214d6a208932"
     cluster="o3e9.30b3214d6a208932"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor bmmedia winner"
     md5_hashes="['6252519bb7a4d87b30b9a4e41320a2cb', 'cb1874b471f5fc747968c44c713e4577', '381b8de9bbb11840e2989b987b6447cc']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2168832,1024) == "48eface216d3f2ee05567603dda9e5d9"
}

