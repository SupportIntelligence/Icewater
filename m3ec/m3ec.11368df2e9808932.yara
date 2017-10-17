import "hash"

rule m3ec_11368df2e9808932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.11368df2e9808932"
     cluster="m3ec.11368df2e9808932"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['3f7688f983e4644efaa6088bcf02d081', '6bdfb2195fb469a5f4e44d2c8df12615', '3f7688f983e4644efaa6088bcf02d081']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(100864,1536) == "0a7dde893da3ff783dc7b304d03d16c1"
}

