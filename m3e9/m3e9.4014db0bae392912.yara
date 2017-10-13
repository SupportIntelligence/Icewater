import "hash"

rule m3e9_4014db0bae392912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4014db0bae392912"
     cluster="m3e9.4014db0bae392912"
     cluster_size="95 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="startpage acfa malicious"
     md5_hashes="['807695bd0415d8a4fa897d7ba662de88', '511eca6d98f9275a7a52a351e40915c7', 'cf682e5075bcbdddf2ebd709ce083219']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(177152,1024) == "5544281402bb85bcb9129f18a798c3e3"
}

