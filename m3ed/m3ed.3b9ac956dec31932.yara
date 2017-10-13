import "hash"

rule m3ed_3b9ac956dec31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac956dec31932"
     cluster="m3ed.3b9ac956dec31932"
     cluster_size="343 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b7fbc712482b835cca90c2924cfd5977', '47929d748752808685534cb62f484ab8', 'dc3ae4fc088ab6d8acdabc450cf2ad9e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(61440,1024) == "fad5720205df679ea754faf4b0429215"
}

