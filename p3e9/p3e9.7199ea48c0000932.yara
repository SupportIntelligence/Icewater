import "hash"

rule p3e9_7199ea48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.7199ea48c0000932"
     cluster="p3e9.7199ea48c0000932"
     cluster_size="1628 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['15a40f602245e201cac57b571f7972c4', '1c581eaa4184c3b787a8bbd7116944d8', '00d49618d253770b57940f7a2df4b6ce']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(3493903,1025) == "b28fde35cceb540730107b616e88ed9c"
}

