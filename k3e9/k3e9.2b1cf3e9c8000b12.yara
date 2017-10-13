import "hash"

rule k3e9_2b1cf3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b1cf3e9c8000b12"
     cluster="k3e9.2b1cf3e9c8000b12"
     cluster_size="498 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['9846900a090f2ea6d90aa02be909202c', 'b49828c1db2fdd4fb08a690b0e659fad', 'bcdffe758445b0e695153ede69d7c2fa']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

