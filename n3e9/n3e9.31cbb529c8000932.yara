import "hash"

rule n3e9_31cbb529c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31cbb529c8000932"
     cluster="n3e9.31cbb529c8000932"
     cluster_size="11013 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['0ef641b6b293ec0782737cedf86c7aac', '0abe43820368ce063100807356605681', '008cdd6304458b322c711408f300481a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(142763,1109) == "3e153f591f3d402724f89d1593be1ca7"
}

