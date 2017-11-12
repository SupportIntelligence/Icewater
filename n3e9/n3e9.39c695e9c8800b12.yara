import "hash"

rule n3e9_39c695e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c695e9c8800b12"
     cluster="n3e9.39c695e9c8800b12"
     cluster_size="4751 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy trojandropper backdoor"
     md5_hashes="['35073fb212a086727a38c6b2ec3b2037', '1e3bdc540fa6239b5dc9bcd06acab59f', '1cc5f06799e33c4f84fc0bc17031bece']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138262,1046) == "66a1aad2b922cc836352280ff4cf1d3b"
}

