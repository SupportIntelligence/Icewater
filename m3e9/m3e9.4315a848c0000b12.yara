import "hash"

rule m3e9_4315a848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4315a848c0000b12"
     cluster="m3e9.4315a848c0000b12"
     cluster_size="73 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack backdoor"
     md5_hashes="['3bf28ad6c65c795300086bea18b99f83', '21966051389478e427a0abba3c579b87', 'f95b05bc8b5cfb7fc9ea4bdc28f1bde6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57856,1024) == "75f3c9fd975d819550e3e61fa3b0e2b0"
}

