import "hash"

rule m3ed_5b8a8e4dc73b1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.5b8a8e4dc73b1932"
     cluster="m3ed.5b8a8e4dc73b1932"
     cluster_size="4 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="chepdu banload agfb"
     md5_hashes="['af416b53b511482daa60eab6117a022f', 'cdaafe7d32d5e924ea715deabeab320f', '9ad35cfef1a2fed252f746d9a20c917a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(59392,1024) == "e38aae22b3c4dd27ba53543250354a69"
}

