import "hash"

rule n3e9_39c61569c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c61569c8800b12"
     cluster="n3e9.39c61569c8800b12"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy trojandropper backdoor"
     md5_hashes="['c9b42a9148b01758cc7a1709ce2b15a6', 'a2cd52aa5c99548561d8543c06899646', 'aecba3de8871f88a94e24bd783c0ee50']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(413696,1076) == "ab5c78a222b72df8502930b7c2966067"
}

