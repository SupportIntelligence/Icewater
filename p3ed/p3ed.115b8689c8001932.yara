import "hash"

rule p3ed_115b8689c8001932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ed.115b8689c8001932"
     cluster="p3ed.115b8689c8001932"
     cluster_size="54 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a7c48676349cd6cca71cb1877cd8fc36', '8c97648360e13e3539f0d64a26e48598', 'ac2d97771308fc5d7567b4c89b6c3eed']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4683776,1024) == "f9cb32322f4a258ae0248c17a27a3766"
}

