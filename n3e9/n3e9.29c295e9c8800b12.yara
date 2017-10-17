import "hash"

rule n3e9_29c295e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c295e9c8800b12"
     cluster="n3e9.29c295e9c8800b12"
     cluster_size="739 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe trojandropper"
     md5_hashes="['0a12a236c24b2be0f3c80f0bbf4908ed', 'a40fd23dc17fa4bb125d7f02cefd40fb', '16f53be8385c7b04a292b10bc6ef7892']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(413184,1076) == "ab5c78a222b72df8502930b7c2966067"
}

