import "hash"

rule m3e9_4919d43acaa00b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4919d43acaa00b32"
     cluster="m3e9.4919d43acaa00b32"
     cluster_size="53 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre trojandownloader kryptik"
     md5_hashes="['c93eb66ad3c91158b6f63157df40cf65', 'ac4ac153d7aee4a39999d235156efebf', 'b1be30e0a5ad321692fade88396be700']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(108544,1024) == "5126aa0d4a5b61f3212fb0a70fd23772"
}

