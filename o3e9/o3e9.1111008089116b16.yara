import "hash"

rule o3e9_1111008089116b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1111008089116b16"
     cluster="o3e9.1111008089116b16"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom wannacryptor wannacry"
     md5_hashes="['07952182c10037777bafd7f8a5306281', 'b0cea234fa2678ce8074c6acbf541089', '07952182c10037777bafd7f8a5306281']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(24576,1024) == "f1466e69e933b23a4a7724312e945fd4"
}

