import "hash"

rule k3e9_3c1c3ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1c3ec9c4000b14"
     cluster="k3e9.3c1c3ec9c4000b14"
     cluster_size="91 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['cef18b62b67fee57e5146f4e82c44824', 'b96fcf626bf481944989680f842a7773', 'c7a2b1e8bd580aca84eab24cc01cdfd9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

