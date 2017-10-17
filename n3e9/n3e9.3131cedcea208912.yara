import "hash"

rule n3e9_3131cedcea208912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3131cedcea208912"
     cluster="n3e9.3131cedcea208912"
     cluster_size="5581 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="downloadguide bundler downloaderguide"
     md5_hashes="['052811980c2d8b49b3850be93f101955', '05f6f218b54722063e299299f55cc732', '071a5cebdc93e125069231a8c4c07f37']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(502912,1088) == "be2f547f15b2bf4e65e73ab9c657e679"
}

