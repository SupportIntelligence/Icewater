import "hash"

rule k3e9_51b13326d5a30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13326d5a30b32"
     cluster="k3e9.51b13326d5a30b32"
     cluster_size="159 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bafb4a5595e6bd3f5b12a739a8c24267', 'c783f58a07603fad746fb0bcb731d868', '379275d760871515e6c5a42cc013f567']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4864,256) == "a123699e38ecb694dc0255cec9d6cbbb"
}

