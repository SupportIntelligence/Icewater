import "hash"

rule o3e9_31329104ea211912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.31329104ea211912"
     cluster="o3e9.31329104ea211912"
     cluster_size="2968 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="vbkrypt eyestye injector"
     md5_hashes="['29a80db62b34dc73c22f1d094af778f2', '05dc7b8611deaa88350fd84dd3293c68', '0799bbe51fd306e13c3d933cd0778f3a']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2074624,1024) == "03c62d5cbf3084513eeab45cb8bb530b"
}

