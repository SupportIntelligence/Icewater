import "hash"

rule n3e9_0109c684dee31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c684dee31916"
     cluster="n3e9.0109c684dee31916"
     cluster_size="17737 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="syncopate unwanted malicious"
     md5_hashes="['016f124d249ae239b6d72d249387b6e7', '0255c15d46e1eefed1e3468a5117bf26', '022c288b075ee07791f7597a28390436']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(293343,1035) == "0c634a7ae3a3912e1c0883fb2a1c1f63"
}

