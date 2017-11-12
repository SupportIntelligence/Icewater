import "hash"

rule m3e9_3334b699c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3334b699c2200b32"
     cluster="m3e9.3334b699c2200b32"
     cluster_size="192 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus barys autorun"
     md5_hashes="['b0aa9ab5cb1b9f1a56504a05dd9db87e', 'c17ac931d738fe7e61a2882e28670bb1', '7e6322d4bf11b9f7d9dbe6f896835a1e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(100352,1024) == "0867d5838f814c53bf52aecce7e57311"
}

