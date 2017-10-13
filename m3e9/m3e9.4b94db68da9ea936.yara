import "hash"

rule m3e9_4b94db68da9ea936
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4b94db68da9ea936"
     cluster="m3e9.4b94db68da9ea936"
     cluster_size="1844 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="wecod symmi urelas"
     md5_hashes="['1e47011b8a72234c1810929fc8eea5d3', '799e1b8d6549c2313a5e501dc57860d6', '97b5cc6d5f8bfbc785a0ad94ce1007ea']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(81920,1024) == "ac1e637480cfb79d008337c529c4687d"
}

