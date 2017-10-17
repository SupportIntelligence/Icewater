import "hash"

rule n3e9_3193a8cbc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3193a8cbc6220b32"
     cluster="n3e9.3193a8cbc6220b32"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom cryptoff malicious"
     md5_hashes="['03749bf1566144cd405afff852dbe7a1', '7ecb56c3fa9795893cacbf3f32708f4b', 'e3ac12aa602fde9f5b2f7f4eef8919bf']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(6144,1024) == "1dfeb8b06b3719a7e14d0260d1b3ccd6"
}

