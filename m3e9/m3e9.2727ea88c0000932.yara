import "hash"

rule m3e9_2727ea88c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2727ea88c0000932"
     cluster="m3e9.2727ea88c0000932"
     cluster_size="2135 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="upatre trojandownloader kryptik"
     md5_hashes="['00f48c083bdc3f0ea393b5aecd38762a', '16d6aa3afc8c122ef41552d581262348', '23e6b56a8bcbf98a9b8a653b20c18dad']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27099,1043) == "3b8d6748a5c57596ee230d317bcd6bbd"
}

