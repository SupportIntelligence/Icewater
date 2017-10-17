import "hash"

rule o3ed_7d4d6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.7d4d6a48c0000b32"
     cluster="o3ed.7d4d6a48c0000b32"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['79768e3befa97f1066ea6c7a0f229604', 'c3f9815d5417da2c42ebd68f2bbd05ce', '09aef22ab43095df5ec7d86f5cb08711']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(635392,1024) == "23ef210ac6a5becc04bd46daffa5e04f"
}

