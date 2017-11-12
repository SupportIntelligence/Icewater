import "hash"

rule m3ed_0934d4d0d94b496e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.0934d4d0d94b496e"
     cluster="m3ed.0934d4d0d94b496e"
     cluster_size="408 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bcce filetour attribute"
     md5_hashes="['5ef4c6bb113a8853b4fade97946572f6', '2c62fd9e0d22c86ef9cfae637acbbb59', '765fa189800f4337331661f0c6fce6bd']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(195082,1034) == "b7d89e074a01b03e4267db494019f89f"
}

