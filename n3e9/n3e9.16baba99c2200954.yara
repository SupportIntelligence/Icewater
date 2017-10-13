import "hash"

rule n3e9_16baba99c2200954
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.16baba99c2200954"
     cluster="n3e9.16baba99c2200954"
     cluster_size="548 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple virut rahack"
     md5_hashes="['1714984c43356ded69ab635851144b8b', '70bba230a1b9e45ca9d1615599246c67', '5a34388b4025449a309c28843c13ba93']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(162784,1028) == "4f535038e929bf7b3ba8d207de4f234e"
}

