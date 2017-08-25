import "hash"

rule o3e7_4134900ed8ab1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.4134900ed8ab1916"
     cluster="o3e7.4134900ed8ab1916"
     cluster_size="8 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virtob virut virux"
     md5_hashes="['f6ad69e31ea183b37add3258bad63893', 'f6ad69e31ea183b37add3258bad63893', 'f6ad69e31ea183b37add3258bad63893']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2541568,1024) == "dfd5b311165162a3681c08d5961a80bb"
}

