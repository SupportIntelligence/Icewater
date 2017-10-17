import "hash"

rule k3e9_139ce164cca39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ce164cca39932"
     cluster="k3e9.139ce164cca39932"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['35da8c1b4a99d61ce5e7d6a99c856499', '35da8c1b4a99d61ce5e7d6a99c856499', '35da8c1b4a99d61ce5e7d6a99c856499']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,1024) == "9d50f87de03c29a87bc27db9932cf548"
}

