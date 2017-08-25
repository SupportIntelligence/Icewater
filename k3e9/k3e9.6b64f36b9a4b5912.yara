import "hash"

rule k3e9_6b64f36b9a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64f36b9a4b5912"
     cluster="k3e9.6b64f36b9a4b5912"
     cluster_size="8 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['c7c84a38f0897ee888209c7a726989d7', 'd771c0b65e7cb25fb8fca8fe0b0209e9', '1744f3e97a26d3c767a05cae552839e7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18612,1036) == "6b61b0cff428f017f29ce22ade6c00dd"
}

