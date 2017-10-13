import "hash"

rule m3e7_15914c0c39436d3a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.15914c0c39436d3a"
     cluster="m3e7.15914c0c39436d3a"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="gofot malicious susp"
     md5_hashes="['750ba65fc8b16694d13254e0bcb999a8', 'd28ae3c7d0f1d08c8297c598ffe3b110', '95156bcde9ebcd27dfb0ff19532a6d38']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(87040,1024) == "150cabbe9c9ffcb61883713df9915dce"
}

