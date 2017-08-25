import "hash"

rule n3e9_0109c684dee31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c684dee31916"
     cluster="n3e9.0109c684dee31916"
     cluster_size="13755 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="syncopate unwanted malicious"
     md5_hashes="['0090415c4e3e044ef65d741c8b1483a8', '00729abb4a3cd553419dca938aa6309f', '00a04410c119f1e32436750396de26fa']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(293343,1035) == "0c634a7ae3a3912e1c0883fb2a1c1f63"
}

