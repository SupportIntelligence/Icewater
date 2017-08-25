import "hash"

rule n3ed_1b0fab19c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b0fab19c2200b12"
     cluster="n3ed.1b0fab19c2200b12"
     cluster_size="125 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b89960acb9b2a71486a4900ee73a5753', 'd7acb9a152cb9ba070cc4682f6c0afdb', 'adc7a76ef76d10ed49fe7c822d63bcfe']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(290816,1024) == "f3e36befd0755f24ecffaff8a4db5c6e"
}

