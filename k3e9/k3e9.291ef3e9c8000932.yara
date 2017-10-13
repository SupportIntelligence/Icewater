import "hash"

rule k3e9_291ef3e9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291ef3e9c8000932"
     cluster="k3e9.291ef3e9c8000932"
     cluster_size="112 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor razy simbot"
     md5_hashes="['baded4ca992ff371bfd72e4b822d74df', '1b12d40e1b61cf946c9d9d385d557c60', 'c8142d3181f19b9101f47fc394b7ed8f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

