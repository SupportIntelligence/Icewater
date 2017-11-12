import "hash"

rule n3e9_469633bda6211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.469633bda6211932"
     cluster="n3e9.469633bda6211932"
     cluster_size="14248 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['00f076765618fd4b96f6c49117b29ea0', '0bc914c0620d298f7cf63fe4a0097504', '0b6a3623ff4d8b761c3f14650a130136']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(235520,1024) == "bffec025a956204692284129053ede1c"
}

