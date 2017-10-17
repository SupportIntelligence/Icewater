import "hash"

rule n3e9_1697552921585247
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1697552921585247"
     cluster="n3e9.1697552921585247"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut allaple virtob"
     md5_hashes="['8dfe92d93300b506ee0c24f3f9430d9e', '5141b826558ee5dd68f46ec832f4c2a1', '194349fa292898fafecff7aef0faffed']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(656896,1024) == "3970a3571ad2ea0f317768921c0c7752"
}

