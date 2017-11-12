import "hash"

rule o3e9_49144e40d9e08912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.49144e40d9e08912"
     cluster="o3e9.49144e40d9e08912"
     cluster_size="3255 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor noobyprotect malicious"
     md5_hashes="['059e8f697a49c2ca8a07787c0db6e09c', '158fdcd763dd64b86c1505bfd720e8cf', '16abb6be2b1e0adf7632d30caa88b7c3']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3116032,1024) == "158f26e6bba485ef0680fe8a8d655bcc"
}

