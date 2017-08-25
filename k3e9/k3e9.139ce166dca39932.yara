import "hash"

rule k3e9_139ce166dca39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ce166dca39932"
     cluster="k3e9.139ce166dca39932"
     cluster_size="9 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b070890d164158b8e6a0b689637afa90', '82224da6416a2975dedbb3c18c364689', 'b4b12e5129819eef904348b5e57d52b2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "a079cfc40f2317e95ff153c3c0dfdaea"
}

