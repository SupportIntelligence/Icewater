import "hash"

rule n3e9_4914d2c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4914d2c9c4000b32"
     cluster="n3e9.4914d2c9c4000b32"
     cluster_size="428 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bbe66edbea3599adeae1281054274f3b', 'b573fd0d52b7cd673605bceb6bbb7143', 'a0f428b37131d71db62bf268a896d92a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(3219,1097) == "9dbcdb80646b5cb4bf3285436fc29f56"
}

