import "hash"

rule m3f0_51a2ab0dc6621132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.51a2ab0dc6621132"
     cluster="m3f0.51a2ab0dc6621132"
     cluster_size="3472 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="gepys kryptik shipup"
     md5_hashes="['90d203281b35533a69f465d225e4f77c', '501edc97fd7e778d9dc0a1d0cbdc8bee', '4ab76a42855190bec86cfd45dc750a5f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(107008,1024) == "05bd76d1c58a8db1e4d70d7ff0e4a389"
}

