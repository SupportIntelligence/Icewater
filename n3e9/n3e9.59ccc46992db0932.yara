import "hash"

rule n3e9_59ccc46992db0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.59ccc46992db0932"
     cluster="n3e9.59ccc46992db0932"
     cluster_size="358 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['7a45c66309746e3594c23c09b9d4f074', '664c7f79791f651478e895b5db40a4a5', '530e2a7de2afcc8e7419f3e88a3d5622']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(616730,1047) == "dd68d691dfcd761e2a378343685d10a8"
}

