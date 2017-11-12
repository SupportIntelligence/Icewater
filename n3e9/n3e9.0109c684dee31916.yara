import "hash"

rule n3e9_0109c684dee31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c684dee31916"
     cluster="n3e9.0109c684dee31916"
     cluster_size="28406 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="syncopate unwanted malicious"
     md5_hashes="['032f46fe57d59546144315e5e0458cd2', '00680649b1fbbfda0771b23b83ec998b', '023740956997ea59e183f6bf65a2374b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(293343,1035) == "0c634a7ae3a3912e1c0883fb2a1c1f63"
}

