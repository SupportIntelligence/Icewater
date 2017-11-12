import "hash"

rule p3ed_115b9ac9c8001932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ed.115b9ac9c8001932"
     cluster="p3ed.115b9ac9c8001932"
     cluster_size="1363 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a5570720f0c40abfd63bf7af1de7452d', 'ad9f8310810297ca61fb3caf4ce3860c', '4e8ff6448027c5c03770028174b14917']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4594176,1536) == "c848423a9ae2e84fcd837368f521bf2c"
}

