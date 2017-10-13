import "hash"

rule m3e7_15914c0c39436d32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.15914c0c39436d32"
     cluster="m3e7.15914c0c39436d32"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="gofot malicious susp"
     md5_hashes="['6f9a339803b62d6c88be109d35029440', '3b4076ae3fa792a23f7fb7d76d9a020a', '15e09644f19483520aa0ef0a5c18b0e9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(87040,1024) == "150cabbe9c9ffcb61883713df9915dce"
}

