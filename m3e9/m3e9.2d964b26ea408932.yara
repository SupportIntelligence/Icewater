import "hash"

rule m3e9_2d964b26ea408932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2d964b26ea408932"
     cluster="m3e9.2d964b26ea408932"
     cluster_size="168 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['8b90d9c040afc131660dfbf192f0a204', 'b1521906cc2b26a62287708cbfc87ee2', 'e9500c33ebe909fad4277690809b648e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "d0d038130aeb82cf87189ddf5ec47c53"
}

