import "hash"

rule k3e9_139da1e499991932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da1e499991932"
     cluster="k3e9.139da1e499991932"
     cluster_size="8867 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="nimnul vjadtre wapomi"
     md5_hashes="['04cf8e41547bddbde0f6261259a0fb8f', '01dfdaa0b17c7143bed10171abf525b0', '0dcb12a832fded0f25dfce581ed0c999']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

