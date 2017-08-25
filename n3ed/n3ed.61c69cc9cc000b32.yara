import "hash"

rule n3ed_61c69cc9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.61c69cc9cc000b32"
     cluster="n3ed.61c69cc9cc000b32"
     cluster_size="727 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['494a60db41328573cde2a4257860fd51', '30ccd5d114bfd5da56678ee6d525d00d', '50d835179466f60a149df43ae7335390']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(137476,1044) == "7f921cd38248f357635f5a700ff85450"
}

