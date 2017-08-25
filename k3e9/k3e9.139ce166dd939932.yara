import "hash"

rule k3e9_139ce166dd939932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ce166dd939932"
     cluster="k3e9.139ce166dd939932"
     cluster_size="47 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c918de7719697f0f5d50667c80552b01', 'abb7de3273af0a4803c5b86f9ecdb86e', 'd8d1039f94640eb9d8d3cbd9d54bdbd8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "a079cfc40f2317e95ff153c3c0dfdaea"
}

