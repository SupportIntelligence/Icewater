import "hash"

rule k3e9_6935a166ddd39b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6935a166ddd39b12"
     cluster="k3e9.6935a166ddd39b12"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['5f40252f536453839353d7ec12a1bd8c', '18b0d780be8e23ee42ab0db50552963b', '5f40252f536453839353d7ec12a1bd8c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "6eb0dc975334c6f733274433d68629c0"
}

