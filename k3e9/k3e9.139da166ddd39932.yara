import "hash"

rule k3e9_139da166ddd39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da166ddd39932"
     cluster="k3e9.139da166ddd39932"
     cluster_size="182 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b341caabcce29c7e0d1eb9d21b96594e', 'b3b97710dafe3658e3428e9e9c4f90c3', 'bfcaf4486b47016c2fe99ed27ec073e9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

