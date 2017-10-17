import "hash"

rule n3e9_2b1cd698c2200b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1cd698c2200b10"
     cluster="n3e9.2b1cd698c2200b10"
     cluster_size="52 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious ransom hpcerber"
     md5_hashes="['c6cc9fbffc860f2b94ea5e1b55819c5c', '33ed64b51bc5f73e6eb204532ef32427', '13ecb955647f06adb89f7444c041f3c9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(429568,1024) == "07d3cd4d4c0c0c3cef63585285f1504f"
}

