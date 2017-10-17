import "hash"

rule n3e9_3192a28bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3192a28bc6220b32"
     cluster="n3e9.3192a28bc6220b32"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious ransom cerber"
     md5_hashes="['2b4d5f1878de68695661be8735ebab88', '6c734fa938deb019a01f033875c3c8ed', '2b4d5f1878de68695661be8735ebab88']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(6144,1024) == "b23e0bf4f41fecfc66d2c1cef87a03c4"
}

