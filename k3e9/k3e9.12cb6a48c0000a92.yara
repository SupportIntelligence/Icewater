import "hash"

rule k3e9_12cb6a48c0000a92
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.12cb6a48c0000a92"
     cluster="k3e9.12cb6a48c0000a92"
     cluster_size="249 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre bublik generickd"
     md5_hashes="['7e4462e4b223ec7e53d08a96fd54525d', 'a84108de8502871d8c7b4d9183d2e682', '630f9579c91b89834d123e90139893db']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1024) == "88b4f217578997aba0b492d801496562"
}

